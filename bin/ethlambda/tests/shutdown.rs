//! The binary shuts down gracefully on SIGTERM, the signal `docker stop`,
//! systemd and Kubernetes send.
//!
//! Runs the real binary in Hive test-driver mode (`HIVE_LEAN_TEST_DRIVER=1`),
//! which reaches the shutdown wait without keys, a genesis or a database, and
//! listens for signals before it logs `Test-driver RPC ready`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

/// Startup compiles leanVM's aggregation bytecode before the test-driver
/// branch, so this is generous.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// A test-driver shutdown has only its HTTP server to stop.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Kills the child if the test ends before it exits, so a failure leaves no
/// process behind.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sigterm_shuts_the_node_down_gracefully() {
    let dir = tempfile::tempdir().expect("temp dir");
    // `node`'s required flags. Test-driver mode reads none of them, so the
    // paths need not exist.
    let required = [
        "--genesis",
        "config.yaml",
        "--validators",
        "validators.yaml",
        "--bootnodes",
        "nodes.yaml",
        "--validator-config",
        "validator-config.yaml",
        "--hash-sig-keys-dir",
        "keys",
        "--node-key",
        "node.key",
        "--node-id",
        "ethlambda_0",
    ];
    let mut node = Node(
        Command::new(env!("CARGO_BIN_EXE_ethlambda"))
            .arg("node")
            .args(required)
            // The OS picks the port, so parallel runs never collide.
            .args(["--api-port", "0"])
            .env("HIVE_LEAN_TEST_DRIVER", "1")
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ethlambda"),
    );
    let lines = read_lines(&mut node.0);

    let mut seen = Vec::new();
    wait_for_line(&lines, &mut seen, "Test-driver RPC ready", READY_TIMEOUT);

    let pid = libc::pid_t::try_from(node.0.id()).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory of ours.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "kill(SIGTERM) failed");

    let status = wait_for_exit(&mut node.0, EXIT_TIMEOUT);
    drain(&lines, &mut seen, EXIT_TIMEOUT);
    let log = seen.join("\n");

    assert_eq!(
        status.code(),
        Some(0),
        "expected a clean exit, got {status}; output:\n{log}"
    );
    assert!(
        seen.iter()
            .any(|line| line.contains("Shutdown signal received") && line.contains("\"SIGTERM\"")),
        "no shutdown line naming SIGTERM; output:\n{log}"
    );
    assert!(
        seen.iter().any(|line| line.contains("Shutdown complete")),
        "no `Shutdown complete`; output:\n{log}"
    );
}

/// Every line the child writes, stdout (its logs) and stderr (an error that
/// ends it) alike, each read on a thread of its own so a full pipe never
/// blocks the child. The channel disconnects once both reach end of file.
fn read_lines(child: &mut Child) -> Receiver<String> {
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel();
    forward_lines(stdout, tx.clone());
    forward_lines(stderr, tx);
    rx
}

fn forward_lines(pipe: impl Read + Send + 'static, tx: Sender<String>) {
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

/// Read what is left once the child has exited, until both pipes close.
fn drain(lines: &Receiver<String>, seen: &mut Vec<String>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => seen.push(line),
            Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                panic!("the node's output did not close within {timeout:?} of its exit")
            }
        }
    }
}

/// Wait for a line containing `needle`, keeping every line read in `seen`.
fn wait_for_line(
    lines: &Receiver<String>,
    seen: &mut Vec<String>,
    needle: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                panic!(
                    "no `{needle}` within {timeout:?}; output:\n{}",
                    seen.join("\n")
                )
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!(
                    "the node exited before `{needle}`; output:\n{}",
                    seen.join("\n")
                )
            }
        }
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the node did not exit within {timeout:?} of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
