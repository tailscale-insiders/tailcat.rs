//! The SFTP subsystem. A file service is rooted in a directory opened
//! with cap-std, whose openat-style lookups keep `..` and symlinks from
//! escaping it; the full-access mode (for shell servers) roots at `/`
//! with the user's home as the working directory.

use std::collections::HashMap;
use std::io;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode};

use super::{FileServeMode, FileService};

enum Open {
    File(cap_std::fs::File),
    Dir(Option<Vec<File>>),
}

pub(crate) struct Sftp {
    root: Dir,
    /// `None` is full access; otherwise the file service mode.
    mode: Option<FileServeMode>,
    /// The virtual working directory ("/" for rooted services).
    cwd: String,
    handles: HashMap<String, Open>,
    next_handle: u64,
    /// For write-only modes: requested path -> the path actually written.
    /// Always empty in other modes.
    wrote: HashMap<String, String>,
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn io_code(e: io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

/// Fails with permission denied unless `allowed`.
fn allow(allowed: bool) -> Result<(), StatusCode> {
    if allowed { Ok(()) } else { Err(StatusCode::PermissionDenied) }
}

/// Lexically normalizes `p` against `cwd` into a path relative to the
/// root, clamping `..` at the root. The root itself is ".".
fn normalize(cwd: &str, p: &str) -> String {
    let joined = if p.starts_with('/') { p.to_string() } else { format!("{cwd}/{p}") };
    let mut parts = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() { ".".into() } else { parts.join("/") }
}

fn attrs(md: &Metadata) -> FileAttributes {
    let secs = |t: io::Result<cap_std::time::SystemTime>| {
        t.ok().map(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32))
    };
    let mut a = FileAttributes {
        size: Some(md.len()),
        atime: secs(md.accessed()),
        mtime: secs(md.modified()),
        ..Default::default()
    };
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        a.permissions = Some(md.mode());
        a.uid = Some(md.uid());
        a.gid = Some(md.gid());
    }
    #[cfg(not(unix))]
    {
        let base = if md.permissions().readonly() { 0o444 } else { 0o644 };
        let kind = if md.is_dir() { 0o040000 | 0o111 } else { 0o100000 };
        a.permissions = Some(base | kind);
    }
    a
}

/// An `ls -l`-style long name, which OpenSSH's sftp shows for `ls -l`.
fn longname(name: &str, a: &FileAttributes) -> String {
    let mode = a.permissions.unwrap_or(0);
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        _ => '-',
    };
    let (perms, uid, gid, size) =
        (super::permission_string(mode), a.uid.unwrap_or(0), a.gid.unwrap_or(0), a.size.unwrap_or(0));
    format!("{kind}{perms}    1 {uid:<8} {gid:<8} {size:>8} {name}")
}

/// A unique name for a drop-box upload: stem.YYYYMMDDhhmmss.<random>.ext.
fn unique_upload_path(requested: &str) -> String {
    let (dir, base) = requested.split_at(requested.rfind('/').map_or(0, |i| i + 1));
    let (stem, ext) = match base.rfind('.') {
        Some(i) if i > 0 => base.split_at(i),
        _ => (base, ""),
    };
    let rnd = hex::encode(rand::random::<[u8; 8]>());
    format!("{dir}{stem}.{}.{rnd}{ext}", utc_timestamp())
}

/// The current UTC time as YYYYMMDDhhmmss.
fn utc_timestamp() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let [y, mo, d, h, m, s] = super::utc_civil(now as i64);
    format!("{y:04}{mo:02}{d:02}{h:02}{m:02}{s:02}")
}

impl Sftp {
    pub fn new(files: Option<FileService>) -> io::Result<Sftp> {
        let (dir, mode, cwd) = match files {
            Some(fs) => (fs.dir, Some(fs.mode), "/".into()),
            None => ("/".into(), None, super::session::current_user().home),
        };
        Ok(Sftp {
            root: Dir::open_ambient_dir(dir, ambient_authority())?,
            mode,
            cwd,
            handles: HashMap::new(),
            next_handle: 1,
            wrote: HashMap::new(),
        })
    }

    fn rel(&self, p: &str) -> String {
        normalize(&self.cwd, p)
    }

    fn write_only(&self) -> bool {
        matches!(self.mode, Some(FileServeMode::WriteOnly | FileServeMode::WriteOnlyTree))
    }

    fn read_only(&self) -> bool {
        self.mode == Some(FileServeMode::ReadOnly)
    }

    /// Reports whether clients may remove, rename and link files.
    fn full_write(&self) -> bool {
        matches!(self.mode, None | Some(FileServeMode::ReadWrite))
    }

    fn new_handle(&mut self, o: Open) -> String {
        let h = format!("h{}", self.next_handle);
        self.next_handle += 1;
        self.handles.insert(h.clone(), o);
        h
    }

    fn file(&self, handle: &str) -> Result<&cap_std::fs::File, StatusCode> {
        match self.handles.get(handle) {
            Some(Open::File(f)) => Ok(f),
            _ => Err(StatusCode::Failure),
        }
    }

    /// Stats `p`, hiding existing files from write-only clients: they may
    /// see only what they wrote, and directories (in flat mode, only the
    /// root).
    fn stat_path(&self, p: &str, follow: bool) -> Result<FileAttributes, StatusCode> {
        let stat = |p: &str| if follow { self.root.metadata(p) } else { self.root.symlink_metadata(p) };
        match self.wrote.get(p) {
            Some(actual) => stat(actual).map(|m| attrs(&m)).map_err(io_code),
            None if !self.write_only() => stat(p).map(|m| attrs(&m)).map_err(io_code),
            None => match stat(p) {
                Ok(m) if m.is_dir() && (p == "." || self.mode == Some(FileServeMode::WriteOnlyTree)) => Ok(attrs(&m)),
                _ => Err(StatusCode::NoSuchFile),
            },
        }
    }

    fn open_write_only(&mut self, p: String, pflags: OpenFlags) -> Result<cap_std::fs::File, StatusCode> {
        allow(!pflags.contains(OpenFlags::READ) && pflags.contains(OpenFlags::WRITE | OpenFlags::CREATE))?;
        let flat = self.mode == Some(FileServeMode::WriteOnly);
        allow(!flat || (p != "." && !p.contains('/')))?;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        let mut actual = if flat { unique_upload_path(&p) } else { p.clone() };
        let mut r = self.root.open_with(&actual, &opts);
        if !flat && matches!(&r, Err(e) if e.kind() == io::ErrorKind::AlreadyExists) {
            actual = unique_upload_path(&p);
            r = self.root.open_with(&actual, &opts);
        }
        let f = r.map_err(io_code)?;
        self.wrote.insert(p, actual);
        Ok(f)
    }

    fn setstat_path(&self, p: &str, a: &FileAttributes) -> io::Result<()> {
        #[cfg(unix)]
        if let Some(mode) = a.permissions {
            use cap_std::fs::PermissionsExt;
            self.root.set_permissions(p, cap_std::fs::Permissions::from_mode(mode & 0o7777))?;
        }
        if let (Some(at), Some(mt)) = (a.atime, a.mtime) {
            use cap_fs_ext::{DirExt, SystemTimeSpec};
            let t = |s: u32| {
                SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.into()),
                ))
            };
            self.root.set_times(p, Some(t(at)), Some(t(mt)))?;
        }
        if let Some(size) = a.size {
            self.root.open_with(p, OpenOptions::new().write(true))?.set_len(size)?;
        }
        Ok(())
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let p = self.rel(&filename);
        let file = if self.write_only() {
            self.open_write_only(p, pflags)?
        } else {
            let wants_write =
                pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::CREATE | OpenFlags::TRUNCATE);
            allow(!(self.read_only() && wants_write))?;
            let (create, exclusive) = (pflags.contains(OpenFlags::CREATE), pflags.contains(OpenFlags::EXCLUDE));
            let mut o = OpenOptions::new();
            o.read(pflags.contains(OpenFlags::READ) || !wants_write)
                .write(pflags.contains(OpenFlags::WRITE))
                .append(pflags.contains(OpenFlags::APPEND))
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .create(create && !exclusive)
                .create_new(create && exclusive);
            self.root.open_with(&p, &o).map_err(io_code)?
        };
        Ok(Handle { id, handle: self.new_handle(Open::File(file)) })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let mut buf = vec![0u8; len.min(256 << 10) as usize];
        let n = read_at(self.file(&handle)?, &mut buf, offset).map_err(io_code)?;
        if n == 0 && len > 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        write_all_at(self.file(&handle)?, &data, offset).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.stat_path(&self.rel(&path), false)? })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: self.stat_path(&self.rel(&path), true)? })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: attrs(&self.file(&handle)?.metadata().map_err(io_code)?) })
    }

    async fn setstat(&mut self, id: u32, path: String, a: FileAttributes) -> Result<Status, Self::Error> {
        allow(!self.read_only())?;
        let p = self.rel(&path);
        let target = if self.write_only() { self.wrote.get(&p).ok_or(StatusCode::PermissionDenied)? } else { &p };
        self.setstat_path(target, &a).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn fsetstat(&mut self, id: u32, handle: String, a: FileAttributes) -> Result<Status, Self::Error> {
        allow(!self.read_only())?;
        let f = self.file(&handle)?;
        if let Some(size) = a.size {
            f.set_len(size).map_err(io_code)?;
        }
        #[cfg(unix)]
        if let Some(mode) = a.permissions {
            use cap_std::fs::PermissionsExt;
            f.set_permissions(cap_std::fs::Permissions::from_mode(mode & 0o7777)).map_err(io_code)?;
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        allow(!self.write_only())?;
        let p = self.rel(&path);
        let dir = if p == "." { self.root.try_clone() } else { self.root.open_dir(&p) }.map_err(io_code)?;
        let files = dir
            .entries()
            .map_err(io_code)?
            .filter_map(|e| {
                let e = e.ok()?;
                let attrs = attrs(&e.metadata().ok()?);
                let filename = e.file_name().to_string_lossy().into_owned();
                Some(File { longname: longname(&filename, &attrs), filename, attrs })
            })
            .collect();
        Ok(Handle { id, handle: self.new_handle(Open::Dir(Some(files))) })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(files)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        match files.take() {
            Some(files) if !files.is_empty() => Ok(Name { id, files }),
            _ => Err(StatusCode::Eof),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        allow(self.full_write())?;
        self.root.remove_file(self.rel(&filename)).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        allow(!matches!(self.mode, Some(FileServeMode::ReadOnly | FileServeMode::WriteOnly)))?;
        let p = self.rel(&path);
        self.root.create_dir(&p).map_err(io_code)?;
        if self.write_only() {
            self.wrote.insert(p.clone(), p);
        }
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        allow(self.full_write())?;
        self.root.remove_dir(self.rel(&path)).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = self.rel(&path);
        let abs = if p == "." { "/".into() } else { format!("/{p}") };
        Ok(Name { id, files: vec![File::dummy(abs)] })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        allow(self.full_write())?;
        self.root.rename(self.rel(&oldpath), &self.root, self.rel(&newpath)).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        allow(!self.write_only())?;
        let t = self.root.read_link_contents(self.rel(&path)).map_err(io_code)?;
        Ok(Name { id, files: vec![File::dummy(t.to_string_lossy())] })
    }

    async fn symlink(&mut self, id: u32, linkpath: String, targetpath: String) -> Result<Status, Self::Error> {
        allow(self.full_write())?;
        // OpenSSH's sftp sends (target, link) despite the spec's order.
        let link = self.rel(&targetpath);
        let target = if self.mode.is_some() { self.rel(&linkpath) } else { linkpath };
        cap_fs_ext::DirExt::symlink(&self.root, target, link).map_err(io_code)?;
        Ok(ok(id))
    }
}

#[cfg(unix)]
fn read_at(f: &cap_std::fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    use cap_std::fs::FileExt;
    let mut n = 0;
    while n < buf.len() {
        match f.read_at(&mut buf[n..], off + n as u64)? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

#[cfg(unix)]
fn write_all_at(f: &cap_std::fs::File, data: &[u8], off: u64) -> io::Result<()> {
    cap_std::fs::FileExt::write_all_at(f, data, off)
}

#[cfg(windows)]
fn read_at(f: &cap_std::fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    cap_std::fs::FileExt::seek_read(f, buf, off)
}

#[cfg(windows)]
fn write_all_at(f: &cap_std::fs::File, mut data: &[u8], mut off: u64) -> io::Result<()> {
    use cap_std::fs::FileExt;
    while !data.is_empty() {
        let n = f.seek_write(data, off)?;
        data = &data[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use russh_sftp::server::Handler as _;

    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize("/", "."), ".");
        assert_eq!(normalize("/", "/a/../b"), "b");
        assert_eq!(normalize("/", "../../etc/passwd"), "etc/passwd");
        assert_eq!(normalize("/home/u", "x"), "home/u/x");
        assert_eq!(normalize("/home/u", "/tmp"), "tmp");
    }

    #[test]
    fn unique_names() {
        let n = unique_upload_path("dir/report.pdf");
        assert!(n.starts_with("dir/report.") && n.ends_with(".pdf"), "{n}");
        assert_eq!(n.len(), "dir/report..pdf".len() + 14 + 1 + 16);
        let n = unique_upload_path(".profile");
        assert!(n.starts_with(".profile.") && !n.contains('/'), "{n}");
        assert_eq!(utc_timestamp().len(), 14);
    }

    #[test]
    fn long_names() {
        let a = FileAttributes { permissions: Some(0o040755), size: Some(3), ..Default::default() };
        assert_eq!(longname("d", &a), "drwxr-xr-x    1 0        0               3 d");
    }

    /// A scratch directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("tailcat-sftp-{}", hex::encode(rand::random::<[u8; 8]>())));
            std::fs::create_dir(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A service root holding `a.txt` and `sub/`, and a secret outside it
    /// that the symlinks `out` (absolute) and `up` (relative) point to.
    fn fixture(mode: FileServeMode) -> (TempDir, Sftp) {
        let t = TempDir::new();
        let root = t.0.join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), "hi").unwrap();
        std::fs::write(t.0.join("secret"), "s3cret").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&t.0, root.join("out")).unwrap();
            std::os::unix::fs::symlink("..", root.join("up")).unwrap();
        }
        let fs = Sftp::new(Some(FileService { dir: root, mode })).unwrap();
        (t, fs)
    }

    const R: OpenFlags = OpenFlags::READ;
    fn wc() -> OpenFlags {
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
    }

    async fn open(fs: &mut Sftp, p: &str, f: OpenFlags) -> Result<String, StatusCode> {
        fs.open(0, p.into(), f, FileAttributes::default()).await.map(|h| h.handle)
    }

    async fn read_file(fs: &mut Sftp, p: &str) -> Result<Vec<u8>, StatusCode> {
        let h = open(fs, p, R).await?;
        let data = fs.read(0, h.clone(), 0, 1 << 10).await.map(|d| d.data);
        fs.close(0, h).await?;
        data
    }

    async fn upload(fs: &mut Sftp, p: &str, data: &[u8]) -> Result<(), StatusCode> {
        let h = open(fs, p, wc()).await?;
        fs.write(0, h.clone(), 0, data.to_vec()).await?;
        fs.close(0, h).await.map(drop)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<_> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn denied<T>(r: Result<T, StatusCode>) {
        assert_eq!(r.err(), Some(StatusCode::PermissionDenied));
    }

    #[tokio::test]
    async fn paths_stay_inside_the_root() {
        let (t, mut fs) = fixture(FileServeMode::ReadWrite);
        assert_eq!(read_file(&mut fs, "a.txt").await.unwrap(), b"hi");
        // `..` clamps at the root.
        assert_eq!(read_file(&mut fs, "../../sub/../a.txt").await.unwrap(), b"hi");
        assert_eq!(read_file(&mut fs, "../secret").await.unwrap_err(), StatusCode::NoSuchFile);
        let n = fs.realpath(0, "sub/../../x".into()).await.unwrap();
        assert_eq!(n.files[0].filename, "/x");
        #[cfg(unix)]
        {
            // Symlinks out of the root don't resolve, absolute or relative.
            assert!(read_file(&mut fs, "out/secret").await.is_err());
            assert!(read_file(&mut fs, "up/secret").await.is_err());
            assert!(fs.stat(0, "out".into()).await.is_err());
            assert!(fs.opendir(0, "up".into()).await.is_err());
            assert!(upload(&mut fs, "out/new", b"x").await.is_err());
            // The links themselves are visible.
            assert!(fs.lstat(0, "out".into()).await.is_ok());
            // New links are made relative to the root, and can't escape it.
            fs.symlink(0, "/a.txt".into(), "link".into()).await.unwrap();
            assert_eq!(read_file(&mut fs, "link").await.unwrap(), b"hi");
            fs.symlink(0, "../secret".into(), "link2".into()).await.unwrap();
            assert_eq!(std::fs::read_link(t.0.join("root/link2")).unwrap(), Path::new("secret"));
            assert_eq!(read_file(&mut fs, "link2").await.unwrap_err(), StatusCode::NoSuchFile);
        }
    }

    #[tokio::test]
    async fn read_only_denies_changes() {
        let (t, mut fs) = fixture(FileServeMode::ReadOnly);
        denied(open(&mut fs, "a.txt", OpenFlags::WRITE).await);
        denied(open(&mut fs, "a.txt", R | OpenFlags::APPEND).await);
        denied(open(&mut fs, "new", wc()).await);
        denied(fs.remove(0, "a.txt".into()).await);
        denied(fs.rename(0, "a.txt".into(), "b".into()).await);
        denied(fs.mkdir(0, "d".into(), FileAttributes::default()).await);
        denied(fs.rmdir(0, "sub".into()).await);
        denied(fs.setstat(0, "a.txt".into(), FileAttributes { size: Some(0), ..Default::default() }).await);
        denied(fs.symlink(0, "a.txt".into(), "l".into()).await);
        let h = open(&mut fs, "a.txt", R).await.unwrap();
        denied(fs.fsetstat(0, h, FileAttributes { size: Some(0), ..Default::default() }).await);
        assert_eq!(std::fs::read(t.0.join("root/a.txt")).unwrap(), b"hi");

        // Listing works, once.
        let h = fs.opendir(0, "/".into()).await.unwrap().handle;
        let listed: Vec<_> = fs.readdir(0, h.clone()).await.unwrap().files.into_iter().map(|f| f.filename).collect();
        assert!(listed.contains(&"a.txt".into()) && listed.contains(&"sub".into()), "{listed:?}");
        assert_eq!(fs.readdir(0, h).await.unwrap_err(), StatusCode::Eof);
        assert_eq!(fs.stat(0, "a.txt".into()).await.unwrap().attrs.size, Some(2));
    }

    #[tokio::test]
    async fn read_write_allows_changes() {
        let (t, mut fs) = fixture(FileServeMode::ReadWrite);
        let root = t.0.join("root");
        upload(&mut fs, "sub/new.txt", b"data").await.unwrap();
        assert_eq!(std::fs::read(root.join("sub/new.txt")).unwrap(), b"data");
        let excl = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        assert_eq!(open(&mut fs, "sub/new.txt", excl).await.unwrap_err(), StatusCode::Failure);
        fs.rename(0, "sub/new.txt".into(), "moved".into()).await.unwrap();
        fs.setstat(0, "moved".into(), FileAttributes { size: Some(2), ..Default::default() }).await.unwrap();
        assert_eq!(std::fs::read(root.join("moved")).unwrap(), b"da");
        fs.remove(0, "moved".into()).await.unwrap();
        fs.mkdir(0, "d".into(), FileAttributes::default()).await.unwrap();
        fs.rmdir(0, "d".into()).await.unwrap();
        fs.rmdir(0, "sub".into()).await.unwrap();
        let mut want = vec!["a.txt"];
        if cfg!(unix) {
            want.extend(["out", "up"]);
        }
        assert_eq!(names(&root), want);
    }

    #[tokio::test]
    async fn write_only_is_a_flat_drop_box() {
        let (t, mut fs) = fixture(FileServeMode::WriteOnly);
        let root = t.0.join("root");
        // Nothing existing is visible or readable.
        assert_eq!(fs.stat(0, "a.txt".into()).await.unwrap_err(), StatusCode::NoSuchFile);
        assert_eq!(fs.stat(0, "sub".into()).await.unwrap_err(), StatusCode::NoSuchFile);
        assert!(fs.stat(0, "/".into()).await.is_ok());
        denied(open(&mut fs, "a.txt", R).await);
        denied(open(&mut fs, "a.txt", R | wc()).await);
        denied(fs.opendir(0, ".".into()).await);
        denied(fs.readlink(0, "out".into()).await);
        denied(fs.mkdir(0, "d".into(), FileAttributes::default()).await);
        denied(open(&mut fs, "sub/x", wc()).await);

        // Uploads land under fresh names, even over existing files.
        upload(&mut fs, "a.txt", b"new").await.unwrap();
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"hi");
        let stored: Vec<_> = names(&root).into_iter().filter(|n| n.starts_with("a.") && n != "a.txt").collect();
        assert_eq!(stored.len(), 1, "{stored:?}");
        assert!(stored[0].ends_with(".txt"));
        assert_eq!(std::fs::read(root.join(&stored[0])).unwrap(), b"new");
        // The uploader may stat and setstat what it wrote, by its name.
        assert_eq!(fs.stat(0, "a.txt".into()).await.unwrap().attrs.size, Some(3));
        fs.setstat(0, "a.txt".into(), FileAttributes { size: Some(1), ..Default::default() }).await.unwrap();
        assert_eq!(std::fs::read(root.join(&stored[0])).unwrap(), b"n");
        denied(fs.setstat(0, "sub".into(), FileAttributes::default()).await);
        denied(fs.remove(0, "a.txt".into()).await);
        denied(fs.rename(0, "a.txt".into(), "b".into()).await);
    }

    #[tokio::test]
    async fn write_only_tree_keeps_names() {
        let (t, mut fs) = fixture(FileServeMode::WriteOnlyTree);
        let root = t.0.join("root");
        assert!(fs.stat(0, "sub".into()).await.unwrap().attrs.is_dir());
        assert_eq!(fs.stat(0, "a.txt".into()).await.unwrap_err(), StatusCode::NoSuchFile);
        fs.mkdir(0, "d".into(), FileAttributes::default()).await.unwrap();
        assert!(fs.stat(0, "d".into()).await.is_ok());
        upload(&mut fs, "d/f.bin", b"1").await.unwrap();
        upload(&mut fs, "d/f.bin", b"2").await.unwrap();
        let stored = names(&root.join("d"));
        assert_eq!(stored.len(), 2);
        assert_eq!(std::fs::read(root.join("d/f.bin")).unwrap(), b"1");
        let other = stored.iter().find(|n| *n != "f.bin").unwrap();
        assert!(other.starts_with("f.") && other.ends_with(".bin"), "{other}");
        assert_eq!(std::fs::read(root.join("d").join(other)).unwrap(), b"2");
        denied(fs.opendir(0, "d".into()).await);
        denied(fs.rmdir(0, "d".into()).await);
        #[cfg(unix)]
        assert!(upload(&mut fs, "out/escaped", b"x").await.is_err());
        assert!(!t.0.join("escaped").exists());
    }
}
