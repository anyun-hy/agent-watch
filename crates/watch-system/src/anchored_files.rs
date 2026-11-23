//! Filesystem operations relative to an open directory, without following
//! links. Used by the user-selected managed entry transaction.
use std::{
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

/// A private, already unlinked, read-only snapshot. The receiving interpreter
/// hashes the bytes it actually reads; it does not reopen the original name.
pub fn unlinked_read_only_bytes(bytes: &[u8]) -> io::Result<File> {
    use std::os::unix::fs::MetadataExt;
    let root = std::fs::canonicalize(std::env::temp_dir())?;
    let dir = Dir::absolute(&root, false)?;
    let mut nonce = [0u8; 16];
    unsafe {
        libc::arc4random_buf(nonce.as_mut_ptr().cast(), nonce.len());
    }
    let name = format!(".cw-script-{:032x}", u128::from_ne_bytes(nonce));
    let mut writer = dir.create(&name, 0o600)?;
    let result = (|| {
        writer.write_all(bytes)?;
        let reader = dir.read(&name)?;
        let written = writer.metadata()?;
        let readable = reader.metadata()?;
        if written.ino() != readable.ino()
            || written.dev() != readable.dev()
            || readable.nlink() != 1
            || readable.len() != bytes.len() as u64
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        dir.remove(&name, false)?;
        if reader.metadata()?.nlink() != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(reader)
    })();
    if result.is_err() {
        if dir
            .read(&name)
            .and_then(|f| f.metadata())
            .ok()
            .zip(writer.metadata().ok())
            .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
        {
            let _ = dir.remove(&name, false);
        }
    }
    result
}

/// Used by the dedicated single-shot helper immediately before exec. Leave
/// the caller's stdin, stdout, stderr and registration descriptors alone.
pub fn inherit_across_exec(file: &File) -> io::Result<i32> {
    let fd = file.as_raw_fd();
    if fd <= 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn name(value: &str) -> io::Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    CString::new(value).map_err(|_| io::ErrorKind::InvalidInput.into())
}

#[derive(Debug)]
pub struct Dir(File);

impl Dir {
    pub fn absolute(path: &Path, create: bool) -> io::Result<Self> {
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut dir = Self(unsafe { File::from_raw_fd(fd) });
        for part in parts {
            let Component::Normal(part) = part else {
                return Err(io::ErrorKind::InvalidInput.into());
            };
            let part =
                std::str::from_utf8(part.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
            dir = match dir.child(part) {
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    match dir.mkdir(part, 0o700) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e),
                    }
                    dir.child(part)?
                }
                other => other?,
            };
        }
        Ok(dir)
    }

    fn open(&self, child: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        let child = name(child)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                child.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                i32::from(mode),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub fn child(&self, child: &str) -> io::Result<Self> {
        self.open(child, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map(Self)
    }
    pub fn read(&self, child: &str) -> io::Result<File> {
        self.open(child, libc::O_RDONLY, 0)
    }
    pub fn create(&self, child: &str, mode: u16) -> io::Result<File> {
        self.open(child, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)
    }
    pub fn mkdir(&self, child: &str, mode: u16) -> io::Result<()> {
        let child = name(child)?;
        let ret = unsafe { libc::mkdirat(self.0.as_raw_fd(), child.as_ptr(), mode) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.0.metadata()
    }

    /// Open a distinct file description so listing never changes the caller's
    /// directory offset. Reject non-UTF8 names instead of normalizing them.
    pub fn names(&self, limit: usize) -> io::Result<Vec<String>> {
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let raw = unsafe { libc::fdopendir(file.as_raw_fd()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _ = file.into_raw_fd();
        struct List(*mut libc::DIR);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let list = List(raw);
        let mut out = Vec::new();
        loop {
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(list.0) };
            if entry.is_null() {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(0) {
                    break;
                }
                return Err(e);
            }
            let value = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if value != "." && value != ".." {
                if out.len() >= limit {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                out.push(value.to_owned());
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn rename(&self, from: &str, to_dir: &Self, to: &str, swap: bool) -> io::Result<()> {
        let from = name(from)?;
        let to = name(to)?;
        let ret = unsafe {
            libc::renameatx_np(
                self.0.as_raw_fd(),
                from.as_ptr(),
                to_dir.0.as_raw_fd(),
                to.as_ptr(),
                if swap {
                    libc::RENAME_SWAP
                } else {
                    libc::RENAME_EXCL
                },
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn remove(&self, child: &str, directory: bool) -> io::Result<()> {
        let child = name(child)?;
        let ret = unsafe {
            libc::unlinkat(
                self.0.as_raw_fd(),
                child.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Clone a single regular file via macOS APFS copy-on-write (`fclonefileat`)
/// without following symlinks on the source file or target parent directory.
///
/// Returns `Ok(true)` when cloned via COW, `Ok(false)` when COW is unsupported
/// for this file or filesystem (e.g. non-APFS, cross-device, or immutable/append
/// BSD flags) so callers can fall back to a regular copy, and `Err` for real
/// I/O, symlink, non-regular-file, or target-exists failures.
#[cfg(target_os = "macos")]
pub fn clone_regular_file(source: &Path, target: &Path) -> io::Result<bool> {
    const CLONE_NOFOLLOW: u32 = 0x0001;
    const CLONE_NOOWNERCOPY: u32 = 0x0002;
    const RESTRICTED_FLAGS: u32 =
        libc::UF_IMMUTABLE | libc::SF_IMMUTABLE | libc::UF_APPEND | libc::SF_APPEND;
    extern "C" {
        fn fclonefileat(
            srcfd: libc::c_int,
            dst_dirfd: libc::c_int,
            dst: *const libc::c_char,
            flags: u32,
        ) -> libc::c_int;
    }

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target missing parent"))?;
    let file_name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target missing file name"))?;
    let file_name_bytes = file_name.as_bytes();
    if file_name_bytes.is_empty()
        || file_name_bytes == b"."
        || file_name_bytes == b".."
        || file_name_bytes.contains(&b'/')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid target file name",
        ));
    }
    let dst_name =
        CString::new(file_name_bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let src_path = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent_path = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

    let src_fd = unsafe {
        libc::open(
            src_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if src_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let src_file = unsafe { File::from_raw_fd(src_fd) };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_file.as_raw_fd(), &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "clone source is not a regular file",
        ));
    }
    if (st.st_flags & RESTRICTED_FLAGS) != 0 {
        return Ok(false);
    }

    let dir_fd = unsafe {
        libc::open(
            parent_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dst_dir = unsafe { File::from_raw_fd(dir_fd) };

    let ret = unsafe {
        fclonefileat(
            src_file.as_raw_fd(),
            dst_dir.as_raw_fd(),
            dst_name.as_ptr(),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EXDEV | libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOSYS) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn clone_regular_file(_source: &Path, _target: &Path) -> io::Result<bool> {
    Ok(false)
}

#[cfg(all(test, target_os = "macos"))]
mod clone_tests {
    use super::clone_regular_file;
    use std::{
        fs,
        io::ErrorKind,
        os::unix::fs::{symlink, MetadataExt},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = root.join(format!("cw-clone-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn clones_regular_file_with_independent_inode_and_cow_isolation() {
        let dir = temp_dir("ok");
        let src = dir.join("source.bin");
        let dst = dir.join("target.bin");
        fs::write(&src, b"original-payload-bytes").unwrap();

        let cloned = clone_regular_file(&src, &dst).unwrap();
        assert!(cloned, "APFS temp dir should support fclonefileat");
        assert_eq!(fs::read(&dst).unwrap(), b"original-payload-bytes");
        assert_ne!(
            fs::symlink_metadata(&src).unwrap().ino(),
            fs::symlink_metadata(&dst).unwrap().ino()
        );

        // Mutating source after clone must not affect the cloned target.
        fs::write(&src, b"mutated-source-content").unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"original-payload-bytes");

        // Re-cloning onto an existing target fails with AlreadyExists.
        let err = clone_regular_file(&src, &dst).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_symlink_source_directory_source_and_symlink_parent() {
        let dir = temp_dir("reject");
        let real = dir.join("real.txt");
        let link = dir.join("link.txt");
        let subdir = dir.join("subdir");
        let link_dir = dir.join("linkdir");
        fs::write(&real, b"hello").unwrap();
        fs::create_dir(&subdir).unwrap();
        symlink(&real, &link).unwrap();
        symlink(&subdir, &link_dir).unwrap();

        assert!(clone_regular_file(&link, &dir.join("out1")).is_err());
        assert!(clone_regular_file(&subdir, &dir.join("out2")).is_err());
        assert!(clone_regular_file(&real, &link_dir.join("out3")).is_err());

        fs::remove_dir_all(dir).unwrap();
    }
}
