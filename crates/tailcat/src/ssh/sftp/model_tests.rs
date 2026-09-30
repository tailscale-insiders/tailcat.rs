//! Model-based tests of the SFTP subsystem, driven by Hegel. A session in
//! each file service mode gets generated requests (opens, reads, writes,
//! closes, stats, listings, renames, removals, mkdirs) and connection
//! drops, and after every step the files on disk are checked against a
//! model of what the requests so far should have left there: nothing
//! changes in read-only mode, read-write mode changes files in place, and
//! a drop box shows only finished uploads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use hegel::TestCase;
use hegel::generators::{self as gs, Generator as _};
use russh_sftp::server::Handler as _;
use tokio::runtime::{Builder, Runtime};

use super::tests::TempDir;
use super::*;

/// The files requests name. The first and last exist from the start; the
/// directory "new" doesn't until it's made.
const FILES: [&str; 5] = ["a.txt", "b", "sub/c", "new/d", "sub/a.txt"];
const DIRS: [&str; 2] = ["sub", "new"];
const MODES: [FileServeMode; 4] =
    [FileServeMode::ReadOnly, FileServeMode::ReadWrite, FileServeMode::WriteOnly, FileServeMode::WriteOnlyTree];

#[derive(Clone, Copy, Debug, hegel::PrettyPrintable)]
enum Flags {
    Read,
    /// Create or truncate.
    Write,
    /// Create, keeping what's there.
    ReadWrite,
    /// Create only if missing.
    Exclusive,
}

impl Flags {
    fn bits(self) -> OpenFlags {
        let wc = OpenFlags::WRITE | OpenFlags::CREATE;
        match self {
            Flags::Read => OpenFlags::READ,
            Flags::Write => wc | OpenFlags::TRUNCATE,
            Flags::ReadWrite => wc | OpenFlags::READ,
            Flags::Exclusive => wc | OpenFlags::EXCLUDE,
        }
    }

    fn readable(self) -> bool {
        matches!(self, Flags::Read | Flags::ReadWrite)
    }

    fn writable(self) -> bool {
        !matches!(self, Flags::Read)
    }
}

enum Kind {
    /// A file opened in place, by its inode in the model.
    File { inode: usize, flags: Flags },
    /// A drop-box upload in progress.
    Upload { requested: String, data: Vec<u8> },
}

/// What a write-only session reports for a name it wrote.
enum Wrote {
    /// Its upload in progress, by handle.
    Open(String),
    /// Its finished upload, by size.
    Done(usize),
}

struct Fs {
    rt: Runtime,
    tmp: TempDir,
    mode: FileServeMode,
    sftp: Sftp,
    open: Vec<(String, Kind)>,
    /// Handles this session has closed.
    closed: Vec<String>,
    /// The visible files the model knows by name, and their inodes: in a
    /// drop box, the originals and the uploads that kept their names.
    names: BTreeMap<String, usize>,
    inodes: Vec<Vec<u8>>,
    dirs: BTreeSet<String>,
    /// The tree at the start, which read-only mode must leave alone.
    initial: Snapshot,
    /// Drop boxes: finished uploads stored under server-chosen names.
    renamed_uploads: Vec<Vec<u8>>,
    wrote: BTreeMap<String, Wrote>,
}

/// Files by path, with their contents, and directories (`None`).
type Snapshot = BTreeMap<String, Option<Vec<u8>>>;

/// Every file (with its contents) and directory (`None`) under `root`.
fn snapshot(root: &Path) -> Snapshot {
    fn walk(root: &Path, dir: &Path, out: &mut Snapshot) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if p.is_dir() {
                out.insert(rel, None);
                walk(root, &p, out);
            } else {
                out.insert(rel, Some(fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn parent(p: &str) -> &str {
    p.rsplit_once('/').map_or("", |(d, _)| d)
}

/// Writes `data` at `off` as pwrite does, zero-filling any gap.
fn write_at(buf: &mut Vec<u8>, off: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let end = off + data.len();
    buf.resize(buf.len().max(end), 0);
    buf[off..end].copy_from_slice(data);
}

impl Fs {
    fn new(mode: FileServeMode) -> Fs {
        let tmp = TempDir::new();
        fs::create_dir(tmp.0.join("sub")).unwrap();
        fs::write(tmp.0.join("a.txt"), "hi").unwrap();
        fs::write(tmp.0.join("sub/a.txt"), "deep").unwrap();
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let sftp = Sftp::new(Some(FileService { dir: tmp.0.clone(), mode })).unwrap();
        Fs {
            rt,
            initial: snapshot(&tmp.0),
            tmp,
            mode,
            sftp,
            open: Vec::new(),
            closed: Vec::new(),
            names: [("a.txt".into(), 0), ("sub/a.txt".into(), 1)].into(),
            inodes: vec![b"hi".to_vec(), b"deep".to_vec()],
            dirs: ["sub".into()].into(),
            renamed_uploads: Vec::new(),
            wrote: BTreeMap::new(),
        }
    }

    fn root(&self) -> PathBuf {
        self.tmp.0.clone()
    }

    fn write_only(&self) -> bool {
        matches!(self.mode, FileServeMode::WriteOnly | FileServeMode::WriteOnlyTree)
    }

    fn parent_exists(&self, p: &str) -> bool {
        let d = parent(p);
        d.is_empty() || self.dirs.contains(d)
    }

    fn draw_file(&self, tc: &TestCase) -> &'static str {
        tc.draw(gs::sampled_from(FILES.to_vec()))
    }

    /// An open handle's index, if there is one.
    fn draw_open(&self, tc: &TestCase) -> Option<usize> {
        (!self.open.is_empty()).then(|| tc.draw(gs::integers::<usize>().max_value(self.open.len() - 1)))
    }

    fn contents<'a>(&'a self, k: &'a Kind) -> &'a [u8] {
        match k {
            Kind::File { inode, .. } => &self.inodes[*inode],
            Kind::Upload { data, .. } => data,
        }
    }

    /// Whether this mode lets `path` be opened with `flags`.
    fn may_open(&self, path: &str, flags: Flags) -> bool {
        let exists = self.names.contains_key(path);
        match (self.mode, flags) {
            (FileServeMode::ReadOnly, f) => !f.writable() && exists,
            (FileServeMode::ReadWrite, Flags::Read) => exists,
            (FileServeMode::ReadWrite, Flags::Exclusive) => self.parent_exists(path) && !exists,
            (FileServeMode::ReadWrite, _) => self.parent_exists(path),
            (_, Flags::Read | Flags::ReadWrite) => false,
            (FileServeMode::WriteOnly, _) => !path.contains('/'),
            (FileServeMode::WriteOnlyTree, _) => self.parent_exists(path),
        }
    }

    /// The size a stat of `path` should report, if it should find it: in
    /// a drop box, only what this session wrote is visible.
    fn visible_size(&self, path: &str) -> Option<usize> {
        if !self.write_only() {
            return self.names.get(path).map(|&i| self.inodes[i].len());
        }
        match self.wrote.get(path)? {
            Wrote::Open(h) => {
                let (_, k) = self.open.iter().find(|(o, _)| o == h).expect("open upload");
                Some(self.contents(k).len())
            }
            Wrote::Done(n) => Some(*n),
        }
    }

    /// What listing `dir` should give.
    fn listing(&self, dir: &str) -> Result<Vec<String>, StatusCode> {
        if self.write_only() {
            return Err(StatusCode::PermissionDenied);
        }
        if !dir.is_empty() && !self.dirs.contains(dir) {
            return Err(StatusCode::NoSuchFile);
        }
        let children = self.names.keys().chain(&self.dirs).filter(|p| parent(p) == dir);
        let base = |p: &String| p.rsplit('/').next().unwrap().to_string();
        let mut want: Vec<_> = children.map(base).collect();
        want.sort();
        Ok(want)
    }

    /// Checks what a drop box holds beyond the names the model knows:
    /// finished uploads under new names, and unfinished ones, under hidden
    /// names.
    fn check_uploads(&self, rest: Snapshot) {
        let hidden = |p: &String| p.rsplit('/').next().unwrap().starts_with('.') && p.ends_with(".part");
        let (temps, finished): (Vec<_>, Vec<_>) = rest.into_iter().partition(|(p, _)| hidden(p));
        let uploading = self.open.iter().filter(|(_, k)| matches!(k, Kind::Upload { .. })).count();
        assert_eq!(temps.len(), uploading, "unfinished uploads: {temps:?}");
        let mut got: Vec<_> = finished.into_iter().map(|(p, f)| f.unwrap_or_else(|| panic!("{p} is a dir"))).collect();
        let mut want = self.renamed_uploads.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want, "visible uploads don't match the finished ones");
    }
}

/// Lists `/dir` to the end, and closes the listing.
async fn list_all(sftp: &mut Sftp, dir: &str) -> Result<Vec<String>, StatusCode> {
    let h = sftp.opendir(0, format!("/{dir}")).await?.handle;
    let mut listed = Vec::new();
    loop {
        match sftp.readdir(0, h.clone()).await {
            Ok(n) => listed.extend(n.files.into_iter().map(|f| f.filename)),
            Err(StatusCode::Eof) => break,
            Err(e) => return Err(e),
        }
    }
    sftp.close(0, h).await?;
    listed.sort();
    Ok(listed)
}

#[hegel::state_machine]
impl Fs {
    #[rule]
    fn open(&mut self, tc: TestCase) {
        let path = self.draw_file(&tc);
        let flags = tc.draw(gs::sampled_from(vec![Flags::Read, Flags::Write, Flags::ReadWrite, Flags::Exclusive]));
        let expect_ok = self.may_open(path, flags);

        let r = self.rt.block_on(self.sftp.open(0, path.into(), flags.bits(), FileAttributes::default()));

        let r = r.map(|h| h.handle);
        assert_eq!(r.is_ok(), expect_ok, "open {path} {flags:?}: {r:?}");
        let Ok(h) = r else { return };
        if self.write_only() {
            self.wrote.insert(path.into(), Wrote::Open(h.clone()));
            self.open.push((h, Kind::Upload { requested: path.into(), data: Vec::new() }));
            return;
        }
        let inode = self.names.get(path).copied().unwrap_or_else(|| {
            self.inodes.push(Vec::new());
            self.names.insert(path.into(), self.inodes.len() - 1);
            self.inodes.len() - 1
        });
        if matches!(flags, Flags::Write) {
            self.inodes[inode].clear();
        }
        self.open.push((h, Kind::File { inode, flags }));
    }

    #[rule]
    fn write(&mut self, tc: TestCase) {
        let Some(i) = self.draw_open(&tc) else { return };
        let len = self.contents(&self.open[i].1).len();
        let off = tc.draw(gs::integers::<usize>().max_value(len + 3));
        let data = tc.draw(gs::binary().max_size(16));
        let h = self.open[i].0.clone();
        let r = self.rt.block_on(self.sftp.write(0, h.clone(), off as u64, data.clone()));
        match &mut self.open[i].1 {
            Kind::File { inode, flags } => {
                // Writing nothing touches nothing, and succeeds.
                assert_eq!(r.is_ok(), flags.writable() || data.is_empty(), "write {h} ({flags:?}): {r:?}");
                if r.is_ok() {
                    write_at(&mut self.inodes[*inode], off, &data);
                }
            }
            Kind::Upload { data: buf, .. } => {
                assert!(r.is_ok(), "write {h}: {r:?}");
                write_at(buf, off, &data);
            }
        }
    }

    #[rule]
    fn read(&mut self, tc: TestCase) {
        let Some(i) = self.draw_open(&tc) else { return };
        let (h, k) = &self.open[i];
        let (h, contents) = (h.clone(), self.contents(k).to_vec());
        let readable = matches!(k, Kind::File { flags, .. } if flags.readable());
        let off = tc.draw(gs::integers::<usize>().max_value(contents.len() + 2));
        let n = tc.draw(gs::integers::<u32>().max_value(24));
        let r = self.rt.block_on(self.sftp.read(0, h.clone(), off as u64, n)).map(|d| d.data);
        if !readable && n > 0 {
            // Opened for writing only.
            assert!(r.is_err(), "read {h}: {r:?}");
            return;
        }
        let start = off.min(contents.len());
        let want = &contents[start..(start + n as usize).min(contents.len())];
        if want.is_empty() && n > 0 {
            assert_eq!(r, Err(StatusCode::Eof), "read {h} at {off}");
        } else {
            assert_eq!(r.as_deref(), Ok(want), "read {h} at {off}");
        }
    }

    #[rule]
    fn close(&mut self, tc: TestCase) {
        let Some(i) = self.draw_open(&tc) else { return };
        let (h, k) = self.open.remove(i);
        let r = self.rt.block_on(self.sftp.close(0, h.clone()));
        assert!(r.is_ok(), "close {h}: {r:?}");
        self.closed.push(h);
        if let Kind::Upload { requested, data } = k {
            self.wrote.insert(requested.clone(), Wrote::Done(data.len()));
            if self.mode == FileServeMode::WriteOnlyTree && !self.names.contains_key(&requested) {
                self.inodes.push(data);
                self.names.insert(requested, self.inodes.len() - 1);
            } else {
                self.renamed_uploads.push(data);
            }
        }
    }

    /// A closed handle is gone for good.
    #[rule]
    fn use_closed(&mut self, tc: TestCase) {
        if self.closed.is_empty() {
            return;
        }
        let i = tc.draw(gs::integers::<usize>().max_value(self.closed.len() - 1));
        let h = self.closed[i].clone();
        let (rt, sftp) = (&self.rt, &mut self.sftp);
        let failed = |r: Result<_, StatusCode>| assert_eq!(r.err(), Some(StatusCode::Failure), "{h}");
        failed(rt.block_on(sftp.read(0, h.clone(), 0, 1)).map(drop));
        failed(rt.block_on(sftp.write(0, h.clone(), 0, b"x".to_vec())).map(drop));
        failed(rt.block_on(sftp.fstat(0, h.clone())).map(drop));
        failed(rt.block_on(sftp.close(0, h.clone())).map(drop));
    }

    #[rule]
    fn stat(&mut self, tc: TestCase) {
        let path = self.draw_file(&tc);
        let want = self.visible_size(path).map(|n| Some(n as u64)).ok_or(StatusCode::NoSuchFile);

        let r = self.rt.block_on(self.sftp.stat(0, path.into())).map(|a| a.attrs.size);

        assert_eq!(r, want, "stat {path}");
    }

    #[rule]
    fn list(&mut self, tc: TestCase) {
        let dir = tc.draw(gs::sampled_from(vec!["", "sub", "new"]));
        let r = self.rt.block_on(list_all(&mut self.sftp, dir));
        assert_eq!(r, self.listing(dir), "list {dir:?}");
    }

    #[rule]
    fn rename(&mut self, tc: TestCase) {
        let (from, to) = (self.draw_file(&tc), self.draw_file(&tc));
        let r = self.rt.block_on(self.sftp.rename(0, from.into(), to.into()));
        if self.mode != FileServeMode::ReadWrite {
            assert_eq!(r.err(), Some(StatusCode::PermissionDenied));
            return;
        }
        assert_eq!(r.is_ok(), self.names.contains_key(from) && self.parent_exists(to), "rename {from} {to}: {r:?}");
        if r.is_ok() {
            let inode = self.names.remove(from).unwrap();
            self.names.insert(to.into(), inode);
        }
    }

    #[rule]
    fn remove(&mut self, tc: TestCase) {
        let path = self.draw_file(&tc);
        let r = self.rt.block_on(self.sftp.remove(0, path.into()));
        if self.mode != FileServeMode::ReadWrite {
            assert_eq!(r.err(), Some(StatusCode::PermissionDenied));
            return;
        }
        assert_eq!(r.is_ok(), self.names.remove(path).is_some(), "remove {path}: {r:?}");
    }

    #[rule]
    fn mkdir(&mut self, tc: TestCase) {
        let dir = tc.draw(gs::sampled_from(&DIRS[..]));
        let r = self.rt.block_on(self.sftp.mkdir(0, dir.into(), FileAttributes::default()));
        if matches!(self.mode, FileServeMode::ReadOnly | FileServeMode::WriteOnly) {
            assert_eq!(r.err(), Some(StatusCode::PermissionDenied));
            return;
        }
        assert_eq!(r.is_ok(), self.dirs.insert(dir.into()), "mkdir {dir}: {r:?}");
    }

    /// The connection drops, and the client connects again.
    #[rule]
    fn reconnect(&mut self, _: TestCase) {
        self.sftp = Sftp::new(Some(FileService { dir: self.root(), mode: self.mode })).unwrap();
        self.open.clear();
        self.closed.clear();
        self.wrote.clear();
    }

    #[invariant(always_run)]
    fn disk_matches_model(&self, _: TestCase) {
        let mut disk = snapshot(&self.root());
        if self.mode == FileServeMode::ReadOnly {
            assert_eq!(disk, self.initial, "read-only mode changed the files");
            return;
        }
        for d in &self.dirs {
            assert_eq!(disk.remove(d), Some(None), "directory {d}");
        }
        for (name, &i) in &self.names {
            assert_eq!(disk.remove(name).flatten().as_ref(), Some(&self.inodes[i]), "file {name}");
        }
        if self.write_only() {
            self.check_uploads(disk);
        } else {
            assert!(disk.is_empty(), "unexpected files: {:?}", disk.keys().collect::<Vec<_>>());
        }
    }
}

#[hegel::test(test_cases = 200)]
fn sftp_state_machine(tc: TestCase) {
    let mode = tc.draw(gs::sampled_from(MODES.to_vec()).print_as_debug());
    hegel::stateful::machine(Fs::new(mode)).steps(40).run(tc);
}
