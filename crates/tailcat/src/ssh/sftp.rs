//! The SFTP subsystem. A file service is rooted in a directory opened
//! with cap-std, whose openat-style lookups keep `..` and symlinks from
//! escaping it; the full-access mode (for shell servers) roots at `/`
//! with the user's home as the working directory.

use std::collections::HashMap;
use std::io;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};

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
    wrote: HashMap<String, String>,
}

fn status(id: u32, code: StatusCode, msg: &str) -> Status {
    Status { id, status_code: code, error_message: msg.to_string(), language_tag: "en-US".to_string() }
}

fn ok(id: u32) -> Status {
    status(id, StatusCode::Ok, "Ok")
}

fn io_code(e: &io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

/// Lexically normalizes `p` against `cwd` into a path relative to the
/// root, clamping `..` at the root. The root itself is ".".
fn normalize(cwd: &str, p: &str) -> String {
    let joined = if p.starts_with('/') { p.to_string() } else { format!("{cwd}/{p}") };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() { ".".to_string() } else { parts.join("/") }
}

fn attrs(md: &Metadata) -> FileAttributes {
    let mut a = FileAttributes {
        size: Some(md.len()),
        atime: md.accessed().ok().map(|t| unix_secs(t.into_std())),
        mtime: md.modified().ok().map(|t| unix_secs(t.into_std())),
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

fn unix_secs(t: std::time::SystemTime) -> u32 {
    t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

/// An `ls -l`-style long name, which OpenSSH's sftp shows for `ls -l`.
fn longname(name: &str, a: &FileAttributes) -> String {
    let mode = a.permissions.unwrap_or(0);
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        _ => '-',
    };
    let mut perms = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        perms.push(if bits & 4 != 0 { 'r' } else { '-' });
        perms.push(if bits & 2 != 0 { 'w' } else { '-' });
        perms.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    format!("{kind}{perms}    1 {:<8} {:<8} {:>8} {name}", a.uid.unwrap_or(0), a.gid.unwrap_or(0), a.size.unwrap_or(0))
}

/// A unique name for a drop-box upload: stem.YYYYMMDDhhmmss.<random>.ext.
fn unique_upload_path(requested: &str) -> String {
    let (dir, base) = match requested.rsplit_once('/') {
        Some((d, b)) => (Some(d), b),
        None => (None, requested),
    };
    let (stem, ext) = match base.rfind('.') {
        Some(i) if i > 0 => (&base[..i], &base[i..]),
        _ => (base, ""),
    };
    let now = chrono_like_utc();
    let mut rnd = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
    let unique = format!("{stem}.{now}.{}{ext}", hex::encode(rnd));
    match dir {
        Some(d) => format!("{d}/{unique}"),
        None => unique,
    }
}

/// The current UTC time as YYYYMMDDhhmmss.
fn chrono_like_utc() -> String {
    let secs =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    format!("{y:04}{mo:02}{d:02}{h:02}{m:02}{s:02}")
}

impl Sftp {
    pub fn new(files: Option<FileService>) -> io::Result<Sftp> {
        match files {
            Some(fs) => Ok(Sftp {
                root: Dir::open_ambient_dir(&fs.dir, ambient_authority())?,
                mode: Some(fs.mode),
                cwd: "/".into(),
                handles: HashMap::new(),
                next_handle: 1,
                wrote: HashMap::new(),
            }),
            None => {
                let home = super::session::current_user().home;
                Ok(Sftp {
                    root: Dir::open_ambient_dir("/", ambient_authority())?,
                    mode: None,
                    cwd: home,
                    handles: HashMap::new(),
                    next_handle: 1,
                    wrote: HashMap::new(),
                })
            }
        }
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

    fn new_handle(&mut self, o: Open) -> String {
        let h = format!("h{}", self.next_handle);
        self.next_handle += 1;
        self.handles.insert(h.clone(), o);
        h
    }

    /// Stats `p`, hiding existing files from write-only clients: they may
    /// see only what they wrote, and (recursively) directories.
    fn stat_path(&self, p: &str, follow: bool) -> Result<FileAttributes, StatusCode> {
        let do_stat = |p: &str| {
            if follow { self.root.metadata(p) } else { self.root.symlink_metadata(p) }
        };
        if !self.write_only() {
            return do_stat(p).map(|m| attrs(&m)).map_err(|e| io_code(&e));
        }
        if let Some(actual) = self.wrote.get(p) {
            return do_stat(actual).map(|m| attrs(&m)).map_err(|e| io_code(&e));
        }
        if self.mode == Some(FileServeMode::WriteOnly) && p != "." {
            return Err(StatusCode::NoSuchFile);
        }
        match do_stat(p) {
            Ok(m) if m.is_dir() => Ok(attrs(&m)),
            _ => Err(StatusCode::NoSuchFile),
        }
    }

    fn open_write_only(&mut self, p: String, pflags: OpenFlags) -> Result<cap_std::fs::File, StatusCode> {
        if pflags.contains(OpenFlags::READ) || !pflags.contains(OpenFlags::WRITE) || !pflags.contains(OpenFlags::CREATE)
        {
            return Err(StatusCode::PermissionDenied);
        }
        let flat = self.mode == Some(FileServeMode::WriteOnly);
        if flat && (p == "." || p.contains('/')) {
            return Err(StatusCode::PermissionDenied);
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        let mut actual = if flat { unique_upload_path(&p) } else { p.clone() };
        let mut r = self.root.open_with(&actual, &opts);
        if !flat && matches!(&r, Err(e) if e.kind() == io::ErrorKind::AlreadyExists) {
            actual = unique_upload_path(&p);
            r = self.root.open_with(&actual, &opts);
        }
        let f = r.map_err(|e| io_code(&e))?;
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
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(s as u64),
                ))
            };
            self.root.set_times(p, Some(t(at)), Some(t(mt)))?;
        }
        if let Some(size) = a.size {
            let f = self.root.open_with(p, OpenOptions::new().write(true))?;
            f.set_len(size)?;
        }
        Ok(())
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _ext: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
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
            if self.read_only() && wants_write {
                return Err(StatusCode::PermissionDenied);
            }
            let mut o = OpenOptions::new();
            o.read(pflags.contains(OpenFlags::READ) || !wants_write)
                .write(pflags.contains(OpenFlags::WRITE))
                .append(pflags.contains(OpenFlags::APPEND))
                .truncate(pflags.contains(OpenFlags::TRUNCATE));
            if pflags.contains(OpenFlags::CREATE) {
                if pflags.contains(OpenFlags::EXCLUDE) {
                    o.create_new(true);
                } else {
                    o.create(true);
                }
            }
            self.root.open_with(&p, &o).map_err(|e| io_code(&e))?
        };
        let handle = self.new_handle(Open::File(file));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        let mut buf = vec![0u8; len.min(256 << 10) as usize];
        let n = read_at(f, &mut buf, offset).map_err(|e| io_code(&e))?;
        if n == 0 && len > 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        write_all_at(f, &data, offset).map_err(|e| io_code(&e))?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let p = self.rel(&path);
        Ok(Attrs { id, attrs: self.stat_path(&p, false)? })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let p = self.rel(&path);
        Ok(Attrs { id, attrs: self.stat_path(&p, true)? })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        let md = f.metadata().map_err(|e| io_code(&e))?;
        Ok(Attrs { id, attrs: attrs(&md) })
    }

    async fn setstat(&mut self, id: u32, path: String, a: FileAttributes) -> Result<Status, Self::Error> {
        let p = self.rel(&path);
        let target = match self.mode {
            Some(FileServeMode::ReadOnly) => return Err(StatusCode::PermissionDenied),
            Some(FileServeMode::WriteOnly | FileServeMode::WriteOnlyTree) => {
                self.wrote.get(&p).cloned().ok_or(StatusCode::PermissionDenied)?
            }
            _ => p,
        };
        self.setstat_path(&target, &a).map_err(|e| io_code(&e))?;
        Ok(ok(id))
    }

    async fn fsetstat(&mut self, id: u32, handle: String, a: FileAttributes) -> Result<Status, Self::Error> {
        if self.read_only() {
            return Err(StatusCode::PermissionDenied);
        }
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        if let Some(size) = a.size {
            f.set_len(size).map_err(|e| io_code(&e))?;
        }
        #[cfg(unix)]
        if let Some(mode) = a.permissions {
            use cap_std::fs::PermissionsExt;
            f.set_permissions(cap_std::fs::Permissions::from_mode(mode & 0o7777)).map_err(|e| io_code(&e))?;
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if self.write_only() {
            return Err(StatusCode::PermissionDenied);
        }
        let p = self.rel(&path);
        let dir = if p == "." { self.root.try_clone() } else { self.root.open_dir(&p) }.map_err(|e| io_code(&e))?;
        let mut files = Vec::new();
        for e in dir.entries().map_err(|e| io_code(&e))? {
            let Ok(e) = e else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(md) = e.metadata() else { continue };
            let a = attrs(&md);
            files.push(File { longname: longname(&name, &a), filename: name, attrs: a });
        }
        let handle = self.new_handle(Open::Dir(Some(files)));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir(files)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        match files.take() {
            Some(files) if !files.is_empty() => Ok(Name { id, files }),
            _ => Err(StatusCode::Eof),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        if self.mode.is_some() && self.mode != Some(FileServeMode::ReadWrite) {
            return Err(StatusCode::PermissionDenied);
        }
        self.root.remove_file(self.rel(&filename)).map_err(|e| io_code(&e))?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        let p = self.rel(&path);
        match self.mode {
            Some(FileServeMode::ReadOnly | FileServeMode::WriteOnly) => return Err(StatusCode::PermissionDenied),
            Some(FileServeMode::WriteOnlyTree) => {
                self.root.create_dir(&p).map_err(|e| io_code(&e))?;
                self.wrote.insert(p.clone(), p);
            }
            _ => self.root.create_dir(&p).map_err(|e| io_code(&e))?,
        }
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        if self.mode.is_some() && self.mode != Some(FileServeMode::ReadWrite) {
            return Err(StatusCode::PermissionDenied);
        }
        self.root.remove_dir(self.rel(&path)).map_err(|e| io_code(&e))?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = self.rel(&path);
        let abs = if p == "." { "/".to_string() } else { format!("/{p}") };
        Ok(Name { id, files: vec![File::dummy(abs)] })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        if self.mode.is_some() && self.mode != Some(FileServeMode::ReadWrite) {
            return Err(StatusCode::PermissionDenied);
        }
        let (a, b) = (self.rel(&oldpath), self.rel(&newpath));
        self.root.rename(a, &self.root, b).map_err(|e| io_code(&e))?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        if self.write_only() {
            return Err(StatusCode::PermissionDenied);
        }
        let t = self.root.read_link_contents(self.rel(&path)).map_err(|e| io_code(&e))?;
        Ok(Name { id, files: vec![File::dummy(t.to_string_lossy().into_owned())] })
    }

    async fn symlink(&mut self, id: u32, linkpath: String, targetpath: String) -> Result<Status, Self::Error> {
        if self.mode.is_some() && self.mode != Some(FileServeMode::ReadWrite) {
            return Err(StatusCode::PermissionDenied);
        }
        use cap_fs_ext::DirExt;
        // OpenSSH's sftp sends (target, link) despite the spec's order.
        let link = self.rel(&targetpath);
        let target = if self.mode.is_some() { self.rel(&linkpath) } else { linkpath };
        DirExt::symlink(&self.root, target, link).map_err(|e| io_code(&e))?;
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
    use cap_std::fs::FileExt;
    f.write_all_at(data, off)
}

#[cfg(windows)]
fn read_at(f: &cap_std::fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    use cap_std::fs::FileExt;
    f.seek_read(buf, off)
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
        assert!(n.starts_with("dir/report.") && n.ends_with(".pdf"));
        assert_eq!(chrono_like_utc().len(), 14);
    }
}
