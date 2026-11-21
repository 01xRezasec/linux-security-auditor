
import subprocess
from types import SimpleNamespace

from linux_security_auditor.checks import ssh_audit


# ==================================================
# audit_ssh() tests
# ==================================================

def test_audit_ssh_with_secure_configuration(monkeypatch):
    secure_config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (secure_config, None, None),
    )

    result = ssh_audit.audit_ssh()

    assert result["module"] == "ssh"
    assert result["status"] == "PASS"
    assert result["scope"] == "global"
    assert len(result["findings"]) == 5
    assert all(
        finding["status"] == "PASS"
        for finding in result["findings"]
    )


def test_audit_ssh_detects_password_authentication_warning(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "yes",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    assert result["status"] == "WARNING"

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "passwordauthentication"
    )

    assert finding["status"] == "WARNING"


def test_audit_ssh_handles_unknown_setting_value(monkeypatch):
    config = {
        "permitrootlogin": "unexpected-value",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    assert result["status"] == "REVIEW"

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "permitrootlogin"
    )

    assert finding["status"] == "UNKNOWN"


def test_audit_ssh_handles_missing_setting(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "x11forwarding"
    )

    assert finding["status"] == "UNKNOWN"
    assert result["status"] == "REVIEW"


def test_audit_ssh_skips_when_privileges_are_insufficient(monkeypatch):
    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (
            None,
            "Insufficient privileges.",
            "SKIPPED",
        ),
    )

    result = ssh_audit.audit_ssh()

    assert result["module"] == "ssh"
    assert result["status"] == "SKIPPED"
    assert result["findings"] == []
    assert "error" in result


def test_audit_ssh_handles_missing_sshd(monkeypatch):
    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (
            None,
            "SSH server executable (sshd) was not found.",
            "ERROR",
        ),
    )

    result = ssh_audit.audit_ssh()

    assert result["status"] == "ERROR"
    assert result["findings"] == []
    assert "sshd" in result["error"]


def test_audit_ssh_handles_configuration_error(monkeypatch):
    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (
            None,
            "Unknown sshd error.",
            "ERROR",
        ),
    )

    result = ssh_audit.audit_ssh()

    assert result["status"] == "ERROR"
    assert result["findings"] == []


def test_audit_ssh_accepts_forced_commands_only(monkeypatch):
    config = {
        "permitrootlogin": "forced-commands-only",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "permitrootlogin"
    )

    assert finding["status"] == "INFO"
    assert result["status"] == "PASS"


def test_audit_ssh_empty_passwords_produce_warning(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "yes",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "permitemptypasswords"
    )

    assert finding["status"] == "WARNING"
    assert result["status"] == "WARNING"


def test_audit_ssh_empty_passwords_with_password_authentication(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "yes",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "yes",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "permitemptypasswords"
    )

    assert finding["status"] == "WARNING"
    assert "Immediate review" in finding["details"]
    assert result["status"] == "WARNING"


def test_audit_ssh_disabled_public_key_is_informational(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "no",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    finding = next(
        item for item in result["findings"]
        if item["setting"] == "pubkeyauthentication"
    )

    assert finding["status"] == "INFO"
    assert result["status"] == "PASS"


def test_audit_ssh_info_does_not_change_pass(monkeypatch):
    config = {
        "permitrootlogin": "forced-commands-only",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "yes",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    assert result["status"] == "PASS"
    assert any(
        item["status"] == "INFO"
        for item in result["findings"]
    )


def test_audit_ssh_uses_connection_context(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    context = {
        "user": "scarynet",
        "host": "client.example",
        "addr": "192.0.2.10",
    }

    received = {}

    def fake_get_config(received_context=None):
        received["context"] = received_context
        return config, None, None

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        fake_get_config,
    )

    result = ssh_audit.audit_ssh(context)

    assert result["status"] == "PASS"
    assert result["scope"] == "connection"
    assert result["context"] == context
    assert received["context"] == context


def test_audit_ssh_global_scope_has_limitations(monkeypatch):
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }

    monkeypatch.setattr(
        ssh_audit,
        "get_effective_ssh_config",
        lambda context=None: (config, None, None),
    )

    result = ssh_audit.audit_ssh()

    assert result["scope"] == "global"
    assert "limitations" in result
    assert result["limitations"]


# ==================================================
# get_effective_ssh_config() tests
# ==================================================

def test_config_skips_without_root_privileges(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 1000)

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert config is None
    assert status == "SKIPPED"
    assert "Insufficient privileges" in error


def test_config_returns_error_when_sshd_is_missing(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ssh_audit.shutil, "which", lambda _: None)

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert config is None
    assert status == "ERROR"
    assert "sshd" in error


def test_config_parses_successful_sshd_output(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "PermitRootLogin PROHIBIT-PASSWORD\n"
                "PasswordAuthentication YES\n"
                "PubkeyAuthentication YES\n"
            ),
            stderr="",
        ),
    )

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert error is None
    assert status is None
    assert config["permitrootlogin"] == "prohibit-password"
    assert config["passwordauthentication"] == "yes"
    assert config["pubkeyauthentication"] == "yes"


def test_config_handles_sshd_execution_failure(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="sshd configuration error",
        ),
    )

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert config is None
    assert status == "ERROR"
    assert "sshd configuration error" in error


def test_config_handles_timeout(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="sshd -T", timeout=15)

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        raise_timeout,
    )

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert config is None
    assert status == "ERROR"
    assert "timed out" in error.lower()


def test_config_handles_os_error(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    def raise_os_error(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        raise_os_error,
    )

    config, error, status = ssh_audit.get_effective_ssh_config()

    assert config is None
    assert status == "ERROR"
    assert "Permission denied" in error


def test_config_builds_connection_context_command(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    received = {}

    def fake_run(command, **kwargs):
        received["command"] = command
        return SimpleNamespace(
            returncode=0,
            stdout="PasswordAuthentication no\n",
            stderr="",
        )

    monkeypatch.setattr(
        ssh_audit.subprocess,
        "run",
        fake_run,
    )

    context = {
        "user": "scarynet",
        "host": "client.example",
        "addr": "192.0.2.10",
        "lport": 22,
    }

    config, error, status = ssh_audit.get_effective_ssh_config(context)

    assert error is None
    assert status is None
    assert config["passwordauthentication"] == "no"
    assert received["command"] == [
        "/usr/sbin/sshd",
        "-T",
        "-C",
        "user=scarynet,host=client.example,addr=192.0.2.10,lport=22",
    ]


def test_config_rejects_incomplete_context(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    context = {
        "user": "scarynet",
        "addr": "192.0.2.10",
    }

    config, error, status = ssh_audit.get_effective_ssh_config(context)

    assert config is None
    assert status == "ERROR"
    assert "requires user, host and addr" in error


def test_config_rejects_unsupported_context_fields(monkeypatch):
    monkeypatch.setattr(ssh_audit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ssh_audit.shutil,
        "which",
        lambda _: "/usr/sbin/sshd",
    )

    context = {
        "user": "scarynet",
        "host": "client.example",
        "addr": "192.0.2.10",
        "invalid": "value",
    }

    config, error, status = ssh_audit.get_effective_ssh_config(context)

    assert config is None
    assert status == "ERROR"
    assert "Unsupported" in error



