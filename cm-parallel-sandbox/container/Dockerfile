# Shared runner image for cm-find-runner and cm-verify-runner.
# Includes an offline exploit toolbox: at runtime there is no internet, so
# every tool `cm verify` may need must be baked in here.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    CLOUDSDK_STORAGE_PARALLEL_COMPOSITE_UPLOAD_ENABLED=False

# Compilers / runtimes and base tools.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg apt-transport-https git jq unzip coreutils procps \
      python3 python3-venv python3-pip nodejs npm golang-go build-essential \
      openjdk-17-jdk-headless php-cli ruby sqlite3 libsqlite3-dev libasan8 binutils \
 && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends google-cloud-cli \
 && (apt-get purge -y sudo || true) \
 && rm -rf /var/lib/apt/lists/*

# Python offline libs (installed at build time only).
RUN python3 -m pip install --no-cache-dir --break-system-packages \
      flask werkzeug jinja2 sqlalchemy requests pyjwt pyyaml lxml django \
      fastapi starlette httpx

# Node offline libs (installed at build time only).
RUN npm install -g --no-fund --no-audit \
      express body-parser jsonwebtoken sqlite3 lodash supertest \
 && npm cache clean --force

# Fail fast instead of hanging on DNS/TCP when the agent tries to fetch deps.
ENV PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    npm_config_offline=true \
    GOFLAGS=-mod=mod \
    GOPROXY=off \
    GOTOOLCHAIN=local \
    GIT_TERMINAL_PROMPT=0 \
    NODE_PATH=/usr/local/lib/node_modules

COPY scripts/ /opt/cm/scripts/
COPY config/ /opt/cm/config/
COPY entrypoint.sh /opt/cm/entrypoint.sh
RUN chmod 0755 /opt/cm/entrypoint.sh /opt/cm/scripts/* \
 && ln -s /opt/cm/scripts/cm-api-token-stats /usr/local/bin/cm-api-token-stats \
 && useradd --create-home --uid 10001 --shell /bin/bash runner

USER runner
ENV HOME=/home/runner \
    PATH=/home/runner/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /home/runner
ENTRYPOINT ["/opt/cm/entrypoint.sh"]
