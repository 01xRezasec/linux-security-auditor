# Linux Security Auditor

A read-only Linux security auditing tool for inspecting SSH server configurations and identifying potentially unsafe settings.

## Features

- Global SSH security auditing
- Connection-specific SSH security auditing
- OpenSSH Match rule evaluation
- Detection of potentially unsafe SSH settings
- Structured security reports
- Interactive command-line interface
- Automated unit and integration tests

## Requirements

- Linux
- Python 3.10 or newer
- OpenSSH server tools (`sshd` and `ssh-keygen`)
- Administrator privileges for SSH configuration auditing

## Installation

### Option 1: Install with pipx

Clone the repository:

```bash
git clone https://github.com/01xRezasec/linux-security-auditor.git
cd linux-security-auditor
```

Install using pipx:

```bash
pipx install .
```

Run:

```bash
sudo "$(command -v linux-security-auditor)"
```

### Option 2: Install with a virtual environment

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install:

```bash
python -m pip install .
```

Run:

```bash
sudo .venv/bin/linux-security-auditor
```

## Usage

Launch the application and follow the interactive menu.

### Global SSH Audit

Inspects the effective global SSH server configuration.

### Connection-Specific SSH Audit

Evaluates SSH settings for a specific connection using:

- Username
- Client hostname
- Client IP address
- Optional server IP address
- Optional server SSH port

OpenSSH Match rules are evaluated for the supplied connection context.

## Security and Safety

- Performs read-only security checks.
- Does not modify SSH configuration.
- Does not restart or stop services.
- Does not automatically apply security changes.
- Does not attempt unauthorized access.
- Use only on systems you own or are authorized to assess.

## Current Scope

Version 0.1.0 focuses on SSH security auditing.

Additional Linux security auditing modules may be introduced in future releases.

## License

Licensed under the MIT License.
See the LICENSE file for details.
