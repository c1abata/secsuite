#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "[tcpent] apt-get not found. This installer supports Ubuntu/Debian/Kali only."
  exit 1
fi

echo "[tcpent] Updating package index..."
sudo apt-get update

echo "[tcpent] Installing base dependencies..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https software-properties-common git jq unzip nmap

if ! command -v pwsh >/dev/null 2>&1; then
  echo "[tcpent] PowerShell not found. Configuring Microsoft package source..."

  . /etc/os-release
  distro="${ID:-}"
  version_id="${VERSION_ID:-}"
  version_major="${version_id%%.*}"

  tmp_deb="/tmp/packages-microsoft-prod.deb"
  download_url=""

  if [[ "$distro" == "ubuntu" ]]; then
    download_url="https://packages.microsoft.com/config/ubuntu/${version_id}/packages-microsoft-prod.deb"
  else
    if [[ -z "$version_major" ]]; then
      version_major="12"
    fi
    download_url="https://packages.microsoft.com/config/debian/${version_major}/packages-microsoft-prod.deb"
  fi

  echo "[tcpent] Downloading $download_url"
  curl -sSfL "$download_url" -o "$tmp_deb"
  sudo dpkg -i "$tmp_deb"
  rm -f "$tmp_deb"

  sudo apt-get update
  sudo apt-get install -y powershell
fi

echo "[tcpent] Running install check..."
pwsh -NoProfile -File "$ROOT_DIR/scripts/Invoke-TcpentInstallCheck.ps1" -OutputPath "$ROOT_DIR/output/install-check"

echo "[tcpent] Installation completed successfully."
