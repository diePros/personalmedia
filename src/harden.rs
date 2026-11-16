//! Process hardening for the server.

/// Marks the process non-dumpable so same-uid processes (for example a
/// compromised OCR child) cannot ptrace it or read `/proc/<pid>/mem`.
/// Call once at startup, before any child process is spawned.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes only integer arguments.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            tracing::warn!("could not clear PR_SET_DUMPABLE");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn harden_process_clears_dumpable() {
        harden_process();
        // SAFETY: prctl(PR_GET_DUMPABLE) takes only integer arguments.
        let v = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(v, 0);
    }
}
