# Backup image: PostgreSQL 17 client (pg_dump/pg_restore) + AWS CLI v2 + bash.
#
# Build from this directory so the image is reproducible by CI:
#   docker build -t registry.example.com/rtip/backup:1.0.0 deploy/backup
#
# The Debian-based postgres image is used on purpose: AWS CLI v2 ships as a
# self-contained glibc bundle, and the Alpine `aws-cli` package is the EOL v1
# line. Copying the bundle from the official image keeps both tools current.
FROM amazon/aws-cli:2.40.3 AS awscli

FROM postgres:17

# Install the distro CA store for libpq TLS connections.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
# Debian already reserves the "backup" user/group (uid/gid 34), so the runtime
# account uses a different name with the uid/gid the CronJob pins.
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws \
    && ln -s /usr/local/aws-cli/v2/current/bin/aws_completer /usr/local/bin/aws_completer \
    && groupadd --gid 10001 rtip \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash rtip

USER 10001:10001

ENTRYPOINT ["/bin/bash"]
