#!/bin/bash
# Deploy the scp/SFTP pass change to the Clone 1 VM through its NAT address, as the local (ungated) admin user.
# Run in a terminal tab: it asks for that user's password once (ssh connection sharing), nothing else.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
host="${1:-Martin@192.168.122.66}"
sock=$(mktemp -u /tmp/thessley-deploy.XXXXXX)
opts=(-F /dev/null -o "ControlPath=$sock" -o ConnectTimeout=10)

ssh "${opts[@]}" -o ControlMaster=yes -o ControlPersist=300 -N -f "$host"
trap 'ssh "${opts[@]}" -O exit "$host" 2>/dev/null || true' EXIT

scp -O "${opts[@]}" "$here/thessley_pam_win/ad_ssh_gate.py" "$here/thessley_pam_win/daemon.py" "$here/scripts/deploy-gate-files.ps1" "$host:"
ssh -tt "${opts[@]}" "$host" powershell -NoProfile -ExecutionPolicy Bypass -File deploy-gate-files.ps1
