
import os
import shutil
import subprocess


SSH_CHECKS = {
    "permitrootlogin": {
        "no": (
            "PASS",
            "Direct root login is disabled",
            "SSH does not permit direct root login.",
        ),
        "prohibit-password": (
            "PASS",
            "Root password login is disabled",
            "Root public-key login may still be permitted.",
        ),
        "forced-commands-only": (
            "INFO",
            "Root login is restricted",
            "Root login is limited to keys configured with forced commands.",
        ),
        "yes": (
            "WARNING",
            "Direct root login is enabled",
            "Review whether direct root access is necessary.",
        ),
    },
    "passwordauthentication": {
        "yes": (
            "WARNING",
            "SSH password authentication is enabled",
            "Password-based authentication is available.",
        ),
        "no": (
            "PASS",
            "SSH password authentication is disabled",
            "Password-based authentication is unavailable.",
        ),
    },
    "pubkeyauthentication": {
        "yes": (
            "PASS",
            "SSH public key authentication is enabled",
            "Public-key authentication is available.",
        ),
        "no": (
            "INFO",
            "SSH public key authentication is disabled",
            "Review whether another suitable authentication method exists.",
        ),
    },
    "permitemptypasswords": {
        "yes": (
            "WARNING",
            "SSH permits empty passwords",
            "Empty-password authentication is permitted by the daemon.",
        ),
        "no": (
            "PASS",
            "Empty SSH passwords are prohibited",
            "Empty-password authentication is disabled.",
        ),
    },
    "x11forwarding": {
        "yes": (
            "INFO",
            "X11 forwarding is enabled",
            "Review whether X11 forwarding is required.",
        ),
        "no": (
            "PASS",
            "X11 forwarding is disabled",
            "X11 forwarding is disabled.",
        ),
    },
}


CONTEXT_FIELDS = ("user", "host", "addr", "laddr", "lport")
REQUIRED_CONTEXT_FIELDS = ("user", "host", "addr")


def parse_ssh_config(output):
    """Parse sshd -T output into a dictionary."""

    config = {}

    for line in output.splitlines():
        parts = line.split(maxsplit=1)

        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip().lower()

    return config



def get_effective_ssh_config(context=None):
    """Read effective SSH configuration, optionally for a connection."""

    if os.geteuid() != 0:
        return None, "Insufficient privileges. Run with sudo.", "SKIPPED"

    sshd_path = shutil.which("sshd")

    if not sshd_path:
        return None, "SSH server executable sshd was not found.", "ERROR"

    command = [sshd_path, "-T"]

    if context is not None:
        if not isinstance(context, dict) or not context:
            return None, "Invalid or empty connection context.", "ERROR"

        if any(
            not isinstance(context.get(key), str) or not context[key].strip()
            for key in REQUIRED_CONTEXT_FIELDS
        ):
            return None, "Context requires user, host and addr.", "ERROR"

        if set(context) - set(CONTEXT_FIELDS):
            return None, "Unsupported connection context field.", "ERROR"

        normalized_context = {}

        for key, value in context.items():
            if key == "lport":
                if isinstance(value, bool):
                    return None, "Invalid local port in connection context.", "ERROR"

                try:
                    port = int(value)
                except (TypeError, ValueError):
                    return None, "Invalid local port in connection context.", "ERROR"

                if not 1 <= port <= 65535:
                    return None, "Local port must be between 1 and 65535.", "ERROR"

                normalized_context[key] = str(port)
                continue

            if not isinstance(value, str) or not value.strip():
                return None, f"Invalid value for context field: {key}.", "ERROR"

            if any(
                char in value
                for char in (",", "=", "\n", "\r", " ", "\t")
            ):
                return None, f"Invalid value for context field: {key}.", "ERROR"

            normalized_context[key] = value

        context_args = ",".join(
            f"{key}={normalized_context[key]}"
            for key in CONTEXT_FIELDS
            if key in normalized_context
        )

        command.extend(["-C", context_args])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if result.returncode != 0:
            error = result.stderr.strip() or "Unknown sshd error."
            return None, error, "ERROR"

        return parse_ssh_config(result.stdout), None, None

    except subprocess.TimeoutExpired:
        return None, "SSH configuration check timed out.", "ERROR"

    except OSError as exc:
        return None, str(exc), "ERROR"


def audit_ssh(context=None):
    """Audit selected effective SSH security settings."""

    config, error, error_status = get_effective_ssh_config(context)

    if error is not None:
        return {
            "module": "ssh",
            "status": error_status,
            "error": error,
            "findings": [],
        }

    findings = []

    for setting, rules in SSH_CHECKS.items():
        value = config.get(setting)

        if value is None:
            findings.append({
                "setting": setting,
                "value": None,
                "status": "UNKNOWN",
                "title": f"Unable to evaluate {setting}",
                "details": "The setting was not returned by sshd.",
            })
            continue

        rule = rules.get(value)

        if rule is None:
            status = "UNKNOWN"
            title = f"Unrecognized value for {setting}"
            details = "Manual review is required."
        else:
            status, title, details = rule

        if (
            setting == "permitemptypasswords"
            and value == "yes"
            and config.get("passwordauthentication") == "yes"
        ):
            details += (
                " Password authentication is also enabled. "
                "Immediate review is recommended."
            )

        findings.append({
            "setting": setting,
            "value": value,
            "status": status,
            "title": title,
            "details": details,
        })

    statuses = {item["status"] for item in findings}

    if "CRITICAL" in statuses:
        overall = "CRITICAL"
    elif "WARNING" in statuses:
        overall = "WARNING"
    elif "UNKNOWN" in statuses:
        overall = "REVIEW"
    else:
        overall = "PASS"

    result = {
        "module": "ssh",
        "status": overall,
        "scope": "connection" if context is not None else "global",
        "findings": findings,
    }

    if context is not None:
        result["context"] = context.copy()
    else:
        result["limitations"] = [
            "Global configuration was checked.",
            "Connection-specific Match rules were not evaluated.",
        ]

    return result

