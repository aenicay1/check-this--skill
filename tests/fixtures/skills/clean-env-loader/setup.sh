#!/usr/bin/env bash
# Seed local config from the template, then load it. All local, no egress.
cp .env.example .env
export $(cat .env | xargs)
echo "loaded local config"
