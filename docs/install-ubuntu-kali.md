# Install TCPENT on Ubuntu and Kali

This guide installs TCPENT v0.1 with safe defaults and validates runtime readiness.

## 1) Requirements

- `sudo` access
- internet access for package installation
- Ubuntu or Kali (Debian-based)

## 2) Clone and enter repository

```bash
git clone <REPO_URL> tcpent
cd tcpent
```

## 3) One-command installation

```bash
chmod +x ./scripts/install-ubuntu-kali.sh
./scripts/install-ubuntu-kali.sh
```

Installer actions:

- installs base dependencies: `curl`, `gnupg`, `jq`, `git`, `unzip`, `nmap`
- installs PowerShell (`pwsh`) via Microsoft package feed when missing
- runs `Invoke-TcpentInstallCheck.ps1`

## 4) Verify installation manually

```bash
pwsh -NoProfile -File ./scripts/Invoke-TcpentInstallCheck.ps1 -OutputPath ./output/install-check
```

Expected status: `Ready`.

## 5) First execution smoke test

```bash
pwsh -NoProfile -File ./scripts/Invoke-TcpentEnvironmentCheck.ps1 -OutputPath ./output
pwsh -NoProfile -File ./scripts/Invoke-TcpentPassiveAssessment.ps1 -OutputPath ./output
```

## 6) Threat validation dry-run

Create `targets.txt` (one target per line) and run:

```bash
pwsh -NoProfile -File ./scripts/Invoke-TcpentThreatValidation.ps1 \
  -OutputPath ./output \
  -TargetsPath ./targets.txt \
  -Profile HybridFullStack
```

## 7) Troubleshooting

- `pwsh: command not found`
  - rerun `./scripts/install-ubuntu-kali.sh`
- `nmap not found`
  - run `sudo apt-get install -y nmap`
- compliance status `Blocked`
  - provide required legal/scope artifacts before execute mode
