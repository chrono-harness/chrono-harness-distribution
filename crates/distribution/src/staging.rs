//! Lifecycle of the native installer's own staging area.
use super::{Result, asset_identity, member_path};
use std::{
    fs::{self, File},
    io::{self, ErrorKind},
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const WORK: &str = ".chrono-harness/distribution-work";
const LOCK: &str = ".chrono-harness/.distribution-lock";
const PREPARED: &str = ".prepared";
const PUBLISHING: &str = ".publishing";

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    asset_identity::same_install_file(
        left.is_file(),
        left.dev(),
        left.ino(),
        right.is_file(),
        right.dev(),
        right.ino(),
    )
}

pub(crate) struct Guard {
    area: PathBuf,
    gate: WriterLock,
    marker: PathBuf,
}

/// End the writer's lock at the operation boundary. A concurrent fork can
/// temporarily share this open file description until its exec closes it.
struct WriterLock(File);

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl Guard {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let marker = member_path(root, LOCK)?;
        let area = member_path(root, WORK)?;
        fs::create_dir_all(&area).map_err(|e| e.to_string())?;
        let gate_path = member_path(&area, "gate")?;
        let gate = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&gate_path)
            .map_err(|e| e.to_string())?;
        gate.try_lock()
            .map_err(|e| format!("installation lock {}: {e}", marker.display()))?;
        let gate = WriterLock(gate);
        match fs::hard_link(&gate_path, &marker) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let existing = fs::symlink_metadata(&marker).map_err(|e| e.to_string())?;
                if !same_file(&gate.0.metadata().map_err(|e| e.to_string())?, &existing) {
                    return Err(format!(
                        "installation lock {}: existing owner unknown",
                        marker.display()
                    ));
                }
            }
            Err(e) => return Err(format!("installation lock {}: {e}", marker.display())),
        }
        Ok(Self { area, gate, marker })
    }

    pub(crate) fn stage(&self) -> Result<Stage> {
        let temp = tempfile::Builder::new()
            .prefix("stage-")
            .rand_bytes(16)
            .tempdir_in(&self.area)
            .map_err(|e| e.to_string())?;
        let reader = File::open(temp.path()).map_err(|e| e.to_string())?;
        reader.lock_shared().map_err(|e| e.to_string())?;
        fs::hard_link(&self.marker, temp.path().join(PREPARED)).map_err(|e| e.to_string())?;
        Ok(Stage {
            path: temp.keep(),
            reader,
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let (Ok(gate), Ok(marker)) = (self.gate.0.metadata(), fs::symlink_metadata(&self.marker))
            && same_file(&gate, &marker)
        {
            let _ = fs::remove_file(&self.marker);
        }
    }
}

pub(crate) struct Stage {
    path: PathBuf,
    reader: File,
}

impl Stage {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn borrow(&self, command: &mut Command) -> io::Result<()> {
        let lease = self.reader.try_clone()?;
        // Only this child receives the shared stage lease. Other stages can proceed on retry.
        unsafe {
            command.pre_exec(move || {
                rustix::io::fcntl_setfd(&lease, rustix::io::FdFlags::empty())
                    .map_err(io::Error::from)
            });
        }
        Ok(())
    }

    pub(crate) fn publish(self, root: &Path, entries: &[(PathBuf, String)]) -> Result<()> {
        let owned = self.path.join(PREPARED);
        let recovery = self.path.join(PUBLISHING);
        fs::rename(&owned, &recovery).map_err(|e| e.to_string())?;
        super::publish(root, &self.path, entries)
            .map_err(|e| format!("{e}; recovery directory: {}", self.path.display()))?;
        fs::rename(recovery, owned).map_err(|e| e.to_string())?;
        drop(self.reader);
        discard(
            &self.path,
            &self.path.parent().unwrap().join("gate"),
            Duration::ZERO,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn discard(path: &Path, gate: &Path, keep: Duration) -> io::Result<bool> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || !asset_identity::install_stage_expired(
            keep.as_secs(),
            meta.modified()?
                .elapsed()
                .ok()
                .map(|elapsed| elapsed.as_secs()),
        )
    {
        return Ok(false);
    }
    let lease = File::open(path)?;
    match lease.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Ok(false),
        Err(fs::TryLockError::Error(e)) => return Err(e),
    }
    let owned = path.join(PREPARED);
    let marker = match fs::symlink_metadata(&owned) {
        Ok(marker) => marker,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !same_file(&fs::metadata(gate)?, &marker) {
        return Ok(false);
    }
    let mut files = Vec::new();
    for item in fs::read_dir(path)? {
        let item = item?;
        if item.path() == owned {
            continue;
        }
        let name = item.file_name();
        let bytes = name.as_encoded_bytes();
        let numbered = bytes
            .strip_prefix(b"backup-")
            .or_else(|| bytes.strip_prefix(b"payload-"))
            .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit));
        if !item.file_type()?.is_file()
            || !(numbered || matches!(bytes, b"release.json" | b"lock" | b"launcher"))
        {
            return Ok(false);
        }
        files.push(item.path());
    }
    for file in files {
        fs::remove_file(file)?;
    }
    fs::remove_file(owned)?;
    fs::remove_dir(path)?;
    Ok(true)
}

pub(crate) fn maintain(root: &Path, seconds: u64) -> Result<usize> {
    if seconds == 0 {
        return Err("retention must be positive".into());
    }
    let area = member_path(root, WORK)?;
    let gate = member_path(&area, "gate")?;
    let file = match File::open(&gate) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.to_string()),
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Ok(0),
        Err(fs::TryLockError::Error(e)) => return Err(e.to_string()),
    }
    let file = WriterLock(file);
    let mut removed = 0;
    for entry in fs::read_dir(&area).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if name
            .as_encoded_bytes()
            .strip_prefix(b"stage-")
            .is_some_and(|id| id.len() == 16 && id.iter().all(u8::is_ascii_alphanumeric))
            && discard(&entry.path(), &gate, Duration::from_secs(seconds))
                .map_err(|e| e.to_string())?
        {
            removed += 1;
        }
    }
    let marker = member_path(root, LOCK)?;
    match fs::symlink_metadata(&marker) {
        Ok(meta) if same_file(&file.0.metadata().map_err(|e| e.to_string())?, &meta) => {
            fs::remove_file(marker).map_err(|e| e.to_string())?
        }
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(removed)
}
