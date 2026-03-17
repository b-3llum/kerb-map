# Installation & Setup

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Tested on 3.10, 3.11, 3.12, 3.14 |
| ldap3 | ≥ 2.9.1 | LDAP connection and queries |
| impacket | ≥ 0.11.0 | Kerberos, RPC, NTLM protocol support |
| rich | ≥ 13.0.0 | Terminal output |
| Network | TCP 389 | LDAP to DC (required) |
| Network | TCP 135 + named pipes | Required for `--aggressive` RPC probes only |

---

## Option A — pipx (Recommended)

pipx installs kerb-map into an isolated virtualenv and exposes the `kerb-map` command globally from any directory. Works on Linux, macOS, and WSL.

```bash
# Install pipx
sudo apt install pipx        # Debian / Kali
sudo pacman -S python-pipx   # Arch Linux
brew install pipx            # macOS
pipx ensurepath

# Clone and install
git clone https://github.com/b-3llum/kerb-map /opt/kerb-map

# macOS / if cloned with sudo — fix permissions first
sudo chown -R $(whoami) /opt/kerb-map

pipx install /opt/kerb-map

# Reload shell
source ~/.zshrc   # or ~/.bashrc

# Verify
kerb-map --help
```

> **Note:** If pipx fails due to impacket dependency conflicts (common on Kali), use Option B.

### How pipx installation works

The `pyproject.toml` defines `kerb-map = "kerb_map.main:main"` as the entry point. When installed via pipx:

1. pipx copies the `kerb_map/` package into an isolated venv
2. `kerb_map/main.py` delegates to `kerb_map/cli.py`
3. `kerb_map/cli.py` contains the full CLI logic
4. The root `kerb-map.py` script is kept for direct `python kerb-map.py` usage

The `pyproject.toml` includes `[tool.setuptools.packages.find]` to include only `kerb_map*` — this prevents the `assets/` directory from confusing setuptools during the build.

---

## Option B — Shell Wrapper

The simplest approach. Creates a global command that calls the root script directly.

```bash
git clone https://github.com/b-3llum/kerb-map /opt/kerb-map
pip install -r /opt/kerb-map/requirements.txt --break-system-packages

sudo bash -c 'printf "#!/usr/bin/env bash\nexec python /opt/kerb-map/kerb-map.py \"\$@\"\n" \
  > /usr/local/bin/kerb-map'
sudo chmod +x /usr/local/bin/kerb-map

# Verify
kerb-map --help
```

---

## Option C — Run Directly

No installation required. Just install dependencies and run the script.

```bash
git clone https://github.com/b-3llum/kerb-map
cd kerb-map
pip install -r requirements.txt --break-system-packages
python kerb-map.py --help
```

---

## Option D — Symlink

```bash
chmod +x /opt/kerb-map/kerb-map.py
sudo ln -s /opt/kerb-map/kerb-map.py /usr/local/bin/kerb-map
```

---

## Platform Notes

### macOS

```bash
# If cloned with sudo, fix permissions before pipx install
sudo chown -R $(whoami) /opt/kerb-map
pipx install /opt/kerb-map
```

### Arch Linux

```bash
sudo pacman -S python-pipx
pipx ensurepath
source ~/.zshrc
git clone https://github.com/b-3llum/kerb-map /opt/kerb-map
pipx install /opt/kerb-map
```

### Kali Linux

```bash
sudo apt install pipx
pipx ensurepath
# If impacket conflicts, use Option B (shell wrapper) instead
```

---

## First Run

```bash
# Basic scan — password auth
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123

# Check stored scan history
kerb-map --list-scans
```

---

## Troubleshooting

### `error: Multiple top-level packages discovered`

setuptools is seeing the `assets/` directory as a package. This is fixed in the current `pyproject.toml`. Pull the latest version:

```bash
cd /opt/kerb-map && git pull
pipx uninstall kerb-map
pipx install /opt/kerb-map
```

### `Permission denied` / `could not create .egg-info`

The directory was cloned with `sudo` and is owned by root:

```bash
sudo chown -R $(whoami) /opt/kerb-map
pipx install /opt/kerb-map
```

### `FileNotFoundError: kerb-map.py`

You have an old version of `kerb_map/main.py` that tries to load the root script as an external file. Pull the latest:

```bash
cd /opt/kerb-map && git pull
pipx uninstall kerb-map && pipx install /opt/kerb-map
```

### `KDC_ERR_PREAUTH_FAILED` or bind errors

```bash
# Verify DC is reachable
ping 192.168.1.10
nc -zv 192.168.1.10 389
```

### Kerberos clock skew

```bash
sudo ntpdate -u 192.168.1.10
```

### impacket import errors

```bash
pip install impacket --break-system-packages --upgrade
```
