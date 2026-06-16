use sentinel_core::{SentinelError, SentinelResult};
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const READ_CHUNK_SIZE: usize = 16 * 1024;

/// Read at most the trailing `max_bytes` from a text file.
pub fn read_tail(path: &Path, max_bytes: u64) -> SentinelResult<String> {
    let mut file = File::open(path).map_err(|err| SentinelError::io(path, err))?;
    let len = file
        .metadata()
        .map_err(|err| SentinelError::io(path, err))?
        .len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))
        .map_err(|err| SentinelError::io(path, err))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| SentinelError::io(path, err))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read a small file as text; returns `Ok(None)` when the file is too large.
pub fn read_small_text(path: &Path, max_bytes: u64) -> SentinelResult<Option<String>> {
    let metadata = fs::metadata(path).map_err(|err| SentinelError::io(path, err))?;
    if metadata.len() > max_bytes {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|err| SentinelError::io(path, err))?;
    Ok(Some(text))
}

/// Hash a file only when it is within the configured size limit.
pub fn hash_file_limited(path: &Path, max_bytes: u64) -> SentinelResult<Option<String>> {
    let metadata = fs::metadata(path).map_err(|err| SentinelError::io(path, err))?;
    if metadata.len() > max_bytes {
        return Ok(None);
    }

    let mut file = File::open(path).map_err(|err| SentinelError::io(path, err))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; READ_CHUNK_SIZE];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|err| SentinelError::io(path, err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(Some(hasher.finalize().to_hex().to_string()))
}

/// Convert a path into a stable display string.
pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Returns whether a file has executable bits on Unix hosts.
pub fn is_executable(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Returns true when the file name is hidden by Unix naming convention.
pub fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.') && name.len() > 1)
        .unwrap_or(false)
}

/// Make a path relative to a configured scan root when possible.
pub fn resolve_under_root(scan_root: &Path, system_path: &Path) -> PathBuf {
    if scan_root.as_os_str().is_empty() || scan_root == Path::new("/") {
        return system_path.to_path_buf();
    }
    match system_path.strip_prefix("/") {
        Ok(relative) => scan_root.join(relative),
        Err(_) => scan_root.join(system_path),
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_file_limited, is_hidden};
    use std::fs;

    #[test]
    fn hash_file_limited_respects_size_limit() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("small.txt");
        fs::write(&path, "abc")?;
        assert!(hash_file_limited(&path, 10)?.is_some());
        assert!(hash_file_limited(&path, 2)?.is_none());
        Ok(())
    }

    #[test]
    fn hidden_file_detection_uses_file_name() {
        assert!(is_hidden(std::path::Path::new("/tmp/.cache.php")));
        assert!(!is_hidden(std::path::Path::new("/tmp/cache.php")));
    }
}
