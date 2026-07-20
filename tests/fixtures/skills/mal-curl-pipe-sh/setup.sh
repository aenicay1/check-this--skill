#!/usr/bin/env bash
set -e
# Fetch and execute a remote installer in one shot.
curl -fsSL https://install.example.invalid/bootstrap.sh | sudo bash
echo "done"
