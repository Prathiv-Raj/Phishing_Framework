#!/bin/bash
set -e

# Fix permissions on bind-mounted data directory so app user can write abphish.db
chown -R app:app /opt/ab-phish/data 2>/dev/null || true
chmod 755 /opt/ab-phish/data 2>/dev/null || true

# Drop from root to app user and run abphish
exec su -s /bin/bash app -c "cd /opt/ab-phish && ./docker/run.sh"
