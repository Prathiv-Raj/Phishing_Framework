# AB-Phish – single runtime image
# Pre-build binary on host first: go build -o abphish_bin .
FROM debian:bookworm-slim

LABEL maintainer="AB-Phish"
LABEL description="AB-Phish Phishing Simulation Platform"
LABEL version="1.0.0"

# Runtime deps (jq, setcap, ca-certificates) are vendored under vendor/bookworm-amd64
# so the image builds offline without apt network access.
COPY vendor/bookworm-amd64/ /
RUN ldconfig

# Create non-root user
RUN useradd -m -d /opt/ab-phish -s /bin/bash app

WORKDIR /opt/ab-phish

# Copy pre-built binary
COPY abphish_bin          ./abphish

# Copy all AB-Phish branded assets
COPY static               ./static
COPY templates            ./templates
COPY db                   ./db
COPY docker               ./docker
COPY config.json          ./config.json
COPY VERSION              ./VERSION

# Create data dir for the sqlite3 db (normally bind-mounted at runtime)
RUN mkdir -p /opt/ab-phish/data

# Set permissions
RUN chown -R app:app /opt/ab-phish && \
    chmod +x /opt/ab-phish/abphish && \
    setcap 'cap_net_bind_service=+ep' /opt/ab-phish/abphish && \
    chmod +x /opt/ab-phish/docker/run.sh

USER app

# Bind admin to all interfaces & create tmp file
RUN sed -i 's/127.0.0.1/0.0.0.0/g' config.json && \
    touch config.json.tmp

# 3333 = Admin UI | 80 = Phishing (HTTP) | 8080 = Phishing (HTTPS)
EXPOSE 3333 80 8080

CMD ["./docker/run.sh"]
