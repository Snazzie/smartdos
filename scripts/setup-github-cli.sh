#!/usr/bin/env bash
set -euo pipefail

if ! command -v sudo >/dev/null 2>&1; then
    echo "Error: sudo is required to install GitHub CLI." >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: this script requires a Debian/Kali-based system with apt-get." >&2
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    if ! command -v wget >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y wget
    fi

    sudo install -d -m 0755 /etc/apt/keyrings
    tmp_key="$(mktemp)"
    trap 'rm -f "$tmp_key"' EXIT
    wget -q -O "$tmp_key" https://cli.github.com/packages/githubcli-archive-keyring.gpg
    sudo install -m 0644 "$tmp_key" /etc/apt/keyrings/githubcli-archive-keyring.gpg

    sudo install -d -m 0755 /etc/apt/sources.list.d
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' \
        "$(dpkg --print-architecture)" \
        | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null

    sudo apt-get update
    sudo apt-get install -y gh
fi

echo
echo "GitHub CLI: $(gh --version | sed -n '1p')"
echo

if gh auth status >/dev/null 2>&1; then
    echo "GitHub CLI is already authenticated."
else
    echo "Starting GitHub browser login..."
    gh auth login --hostname github.com --git-protocol https --web
fi

echo
echo "Authentication status:"
gh auth status

echo
echo "Next step from the smartdos repository:"
echo "  git push origin main"
