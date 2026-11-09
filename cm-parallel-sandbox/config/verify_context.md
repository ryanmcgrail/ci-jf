IMPORTANT: EXECUTION ENVIRONMENT CONSTRAINTS (read before planning)

1. AIR-GAPPED. This is an offline Cloud Run sandbox with NO internet access. Only the Google APIs that
   CodeMender itself uses are reachable. The following WILL hang or fail, so do NOT run them, not even
   once to check: pip/pip3/uv install, npm/yarn/pnpm install, npx <remote pkg>, go get / go mod download,
   cargo fetch or builds needing new crates, mvn/gradle dependency resolution, gem/bundle install,
   composer install, apt-get/apk/yum, git clone/fetch/pull/submodule update, curl/wget to any external
   host, and pulling container images.

2. NO PRIVILEGES, NO CONTAINERS, NO SERVICES. You are a non-root user with no sudo. There is no Docker,
   docker-compose, podman, systemd or package manager. No database/cache/broker servers (PostgreSQL,
   MySQL, Redis, MongoDB, Kafka, Elasticsearch) are running or installable. Use sqlite3, in-memory
   fakes, or stdlib servers bound to 127.0.0.1 instead.

3. SOURCE ONLY. $REPO_DIR is a depth-1 source checkout of $REPO_ID (primary language: $LANGUAGE).
   Its third-party dependencies are NOT installed unless they appear in the inventory below. Do not
   try to build or start the whole application if that needs missing dependencies.

4. OFFLINE TOOL INVENTORY (exact list of what exists on this machine; nothing else is available):
$TOOL_INVENTORY
