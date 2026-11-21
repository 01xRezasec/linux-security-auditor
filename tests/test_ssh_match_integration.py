
import shutil
import subprocess

import pytest

from linux_security_auditor.checks import ssh_audit


@pytest.fixture
def real_sshd_match_config(tmp_path, monkeypatch):
    """
    Prepare a temporary OpenSSH configuration with real Match rules.
    The system SSH configuration is never modified.
    """

    sshd_path = shutil.which("sshd")
    ssh_keygen_path = shutil.which("ssh-keygen")

    if not sshd_path or not ssh_keygen_path:
        pytest.skip("sshd or ssh-keygen is not installed.")

    host_key = tmp_path / "ssh_host_ed25519_key"

    key_result = subprocess.run(
        [
            ssh_keygen_path,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(host_key),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if key_result.returncode != 0:
        pytest.skip("Unable to generate temporary SSH host key.")

    config_file = tmp_path / "sshd_config"

    config_file.write_text(
        f"""
Port 2222
HostKey {host_key}
PidFile {tmp_path / "sshd.pid"}

PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no

Match User scarynet
    PasswordAuthentication no

Match Address 192.0.2.0/24
    X11Forwarding yes

Match Host *.example.test
    PermitRootLogin prohibit-password

Match User scarynet Address 198.51.100.0/24
    PubkeyAuthentication no
""".strip()
        + "\n",
        encoding="utf-8",
    )

    original_run = subprocess.run

    validation = original_run(
        [sshd_path, "-t", "-f", str(config_file)],
        capture_output=True,
        text=True,
        check=False,
    )

    if validation.returncode != 0:
        pytest.fail(
            "Temporary SSH configuration is invalid: "
            + validation.stderr
        )

    def run_with_test_config(command, **kwargs):
        test_command = [
            sshd_path,
            "-f",
            str(config_file),
            *command[1:],
        ]

        return original_run(test_command, **kwargs)

    # Bypass the application's root check only for this test.
    # The generated temporary host key is readable by the test user.
    monkeypatch.setattr(
        ssh_audit.os,
        "geteuid",
        lambda: 0,
    )

    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda name: sshd_path if name == "sshd" else None,
    )

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        run_with_test_config,
    )


def get_finding(result, setting):
    return next(
        item
        for item in result["findings"]
        if item["setting"] == setting
    )


def test_match_user_applies_user_specific_configuration(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "scarynet",
        "host": "client.invalid",
        "addr": "203.0.113.10",
    })

    finding = get_finding(result, "passwordauthentication")

    assert finding["value"] == "no"
    assert finding["status"] == "PASS"


def test_match_address_applies_ip_specific_configuration(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "nobody",
        "host": "client.invalid",
        "addr": "192.0.2.10",
    })

    finding = get_finding(result, "x11forwarding")

    assert finding["value"] == "yes"
    assert finding["status"] == "INFO"


def test_match_host_applies_hostname_specific_configuration(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "nobody",
        "host": "workstation.example.test",
        "addr": "203.0.113.10",
    })

    finding = get_finding(result, "permitrootlogin")

    assert finding["value"] == "prohibit-password"
    assert finding["status"] == "PASS"


def test_match_combined_conditions_require_all_conditions(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "scarynet",
        "host": "client.invalid",
        "addr": "198.51.100.25",
    })

    finding = get_finding(result, "pubkeyauthentication")

    assert finding["value"] == "no"
    assert finding["status"] == "INFO"


def test_match_combined_conditions_do_not_apply_to_other_user(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "nobody",
        "host": "client.invalid",
        "addr": "198.51.100.25",
    })

    finding = get_finding(result, "pubkeyauthentication")

    assert finding["value"] == "yes"
    assert finding["status"] == "PASS"


def test_match_rules_do_not_apply_when_conditions_do_not_match(
    real_sshd_match_config,
):
    result = ssh_audit.audit_ssh({
        "user": "nobody",
        "host": "client.invalid",
        "addr": "203.0.113.10",
    })

    password = get_finding(result, "passwordauthentication")
    x11 = get_finding(result, "x11forwarding")
    root = get_finding(result, "permitrootlogin")

    assert password["value"] == "yes"
    assert x11["value"] == "no"
    assert root["value"] == "yes"

