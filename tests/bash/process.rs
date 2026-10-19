//! Bounded child capture reused from the offline consumer gate; no host shell.
use std::{
    os::{fd::AsRawFd as _, unix::process::CommandExt as _},
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
struct GroupChild(std::process::Child, bool);
impl GroupChild {
    fn stop_group(&self) {
        // SAFETY: this unreaped child pins the freshly created PGID.
        unsafe {
            libc::kill(-i32::try_from(self.0.id()).unwrap(), libc::SIGKILL);
        }
    }
}
impl Drop for GroupChild {
    fn drop(&mut self) {
        if self.1 {
            return;
        }
        self.stop_group();
        // SIGKILL cleanup is synchronous; kernel stalls cannot have an absolute bound.
        let _ = self.0.wait();
    }
}
pub(super) fn bounded_invoke(cli: &Path, cwd: &Path, phase: &'static str, args: &[&str]) -> Output {
    const LIMIT: usize = 1024 * 1024;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut child = GroupChild(
        Command::new(cli)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", cwd)
            .env("PATH", "")
            .env("LC_ALL", "C")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
        false,
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    for descriptor in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        // SAFETY: these are exclusively owned pipe readers, not shared terminal OFDs.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
    }
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut closed = [false; 2];
    let mut exited = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "Bash {phase}: subprocess exceeded 60s; captured stderr={}",
            String::from_utf8_lossy(&errors)
        );
        if !exited {
            // SAFETY: initialized writable siginfo; WNOWAIT preserves PID ownership.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let observed = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.0.id(),
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if observed < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted
                );
            } else if unsafe { info.si_pid() } != 0 {
                exited = true;
                child.stop_group(); // Before reap, including descendants still holding pipes.
            }
        }
        for (index, (reader, bytes)) in [
            (&mut stdout as &mut dyn std::io::Read, &mut output),
            (&mut stderr as &mut dyn std::io::Read, &mut errors),
        ]
        .into_iter()
        .enumerate()
        {
            let mut buffer = [0; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        closed[index] = true;
                        break;
                    }
                    Ok(count) => {
                        assert!(
                            bytes.len() + count <= LIMIT,
                            "Bash {phase}: output exceeds 1 MiB"
                        );
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("Bash {phase}: capture failed: {error}"),
                }
            }
        }
        if exited && closed == [true, true] {
            break;
        }
        let mut polls = [
            libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: live descriptors and writable two-element array, bounded poll.
        unsafe {
            libc::poll(polls.as_mut_ptr(), 2, 10);
        }
    }
    let status = child.0.wait().unwrap();
    // The group was killed before this reap; don't reuse its numeric PGID in Drop.
    child.1 = true;
    let result = Output {
        status,
        stdout: output,
        stderr: errors,
    };
    result
}

#[test]
fn noninteractive_subprocess_receives_null_stdin() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("stdin-probe-only"),
        b"controlled child fixture",
    )
    .unwrap();
    let result = bounded_invoke(
        &std::env::current_exe().unwrap(),
        directory.path(),
        "stdin fixture",
        &[
            "execution::process::stdin_probe_child",
            "--exact",
            "--nocapture",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("SYROX_NULL_STDIN_VERIFIED"));
}
#[test]
fn stdin_probe_child() {
    if std::fs::read("stdin-probe-only").ok().as_deref() != Some(b"controlled child fixture") {
        return;
    }
    use std::io::{IsTerminal as _, Read as _};
    assert!(!std::io::stdin().is_terminal());
    let mut byte = [0];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    println!("SYROX_NULL_STDIN_VERIFIED");
}
