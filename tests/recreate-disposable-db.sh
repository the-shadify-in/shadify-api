#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------------------------
# Disposable PostgreSQL Database Recreation & Verification Pipeline (Revision 15)
# Guarantees:
# 1. Configurable, validated psql executable resolution via PATH or standard directories.
# 2. Strict dedicated database allowlist: only explicitly allowlisted disposable names permitted.
# 3. Mandatory destructive-operation opt-in: CONFIRM_DISPOSABLE_DB_DESTRUCTION=1 required.
# 4. Connected server pre-flight verification: inspects server port and local socket before any drop.
# 5. Mandatory -v ON_ERROR_STOP=1 on 100% of psql invocations (fails process immediately if SQL error occurs).
# 6. Canonical schema sequencing: 0_init baseline -> fixture helpers -> migrations 000, 001, 002, 003.
# ---------------------------------------------------------------------------------------------

PORT="${PGPORT:-5433}"
HOST="${PGHOST:-/tmp}"
USER="${PGUSER:-cvs}"
DB="${PGDATABASE:-shadify_migrated_test}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Explicit Destructive-Operation Opt-In Guard (F15 Safety Requirement)
if [[ "${CONFIRM_DISPOSABLE_DB_DESTRUCTION:-0}" != "1" ]]; then
  echo "FATAL SAFETY VIOLATION: Destructive database recreation requires explicit opt-in." >&2
  echo "Set CONFIRM_DISPOSABLE_DB_DESTRUCTION=1 to authorize dropping and recreating disposable test database." >&2
  exit 1
fi

# 2. Dedicated Disposable Database Allowlist Guard (F15 Safety Requirement)
ALLOWED_DISPOSABLE_DBS=("shadify_migrated_test" "shadify_disposable_test" "shadify_concurrency_test")
IS_ALLOWED=0
for allowed in "${ALLOWED_DISPOSABLE_DBS[@]}"; do
  if [[ "${DB}" == "${allowed}" ]]; then
    IS_ALLOWED=1
    break
  fi
done

if [[ "${IS_ALLOWED}" -ne 1 ]]; then
  echo "FATAL SAFETY VIOLATION: Database '${DB}' is not in the dedicated disposable database allowlist: (${ALLOWED_DISPOSABLE_DBS[*]}). Aborting." >&2
  exit 1
fi

# 3. Target Host and Port Scope Guards (Dedicated Test Instance Enforced)
if [[ "${HOST}" != "localhost" && "${HOST}" != "127.0.0.1" && "${HOST}" != "/tmp"* ]]; then
  echo "FATAL SAFETY VIOLATION: Target host '${HOST}' is not a local test socket or loopback address. Aborting." >&2
  exit 1
fi

# Port 5433 is the dedicated disposable test instance port.
# If port 5432 (standard dev instance) is attempted, require explicit ALLOW_PORT_5432=1 override.
if [[ "${PORT}" == "5432" && "${ALLOW_PORT_5432:-0}" != "1" ]]; then
  echo "FATAL SAFETY VIOLATION: Port 5432 is the standard development port. Dedicated disposable test port 5433 must be used." >&2
  echo "To override for local testing on 5432, explicitly pass ALLOW_PORT_5432=1 along with CONFIRM_DISPOSABLE_DB_DESTRUCTION=1." >&2
  exit 1
fi

if [[ "${PORT}" != "5433" && "${PORT}" != "5432" ]]; then
  echo "FATAL SAFETY VIOLATION: Target port '${PORT}' is not an authorized test port (5433). Aborting." >&2
  exit 1
fi

# 4. Resolve and Validate psql Executable
PSQL_BIN=""
if command -v psql >/dev/null 2>&1; then
  PSQL_BIN="$(command -v psql)"
elif [[ -x "/opt/homebrew/bin/psql" ]]; then
  PSQL_BIN="/opt/homebrew/bin/psql"
elif [[ -x "/usr/local/bin/psql" ]]; then
  PSQL_BIN="/usr/local/bin/psql"
elif [[ -x "/usr/bin/psql" ]]; then
  PSQL_BIN="/usr/bin/psql"
fi

if [[ -z "${PSQL_BIN}" || ! -x "${PSQL_BIN}" ]]; then
  echo "ERROR: Valid psql executable could not be resolved in PATH or standard directories." >&2
  exit 1
fi

echo "Resolved psql executable: ${PSQL_BIN} ($("${PSQL_BIN}" --version))"

# Define base psql command with mandatory ON_ERROR_STOP=1
RUN_PSQL=("${PSQL_BIN}" -v ON_ERROR_STOP=1 -p "${PORT}" -h "${HOST}" -U "${USER}")

# 5. Connected Server & Target Database Pre-Flight Validation
# Queries the live connected server directly before executing any destructive operations.
CONNECTED_USER=$("${RUN_PSQL[@]}" -d postgres -t -A -c "SELECT current_user;")
CONNECTED_SERVER_PORT=$("${RUN_PSQL[@]}" -d postgres -t -A -c "SHOW port;")
CONNECTED_DATA_DIR=$("${RUN_PSQL[@]}" -d postgres -t -A -c "SHOW data_directory;")
CONNECTED_SERVER_ADDR=$("${RUN_PSQL[@]}" -d postgres -t -A -c "SELECT COALESCE(inet_server_addr()::text, 'unix_domain_socket');")
CONNECTED_SOCKET_DIR=$("${RUN_PSQL[@]}" -d postgres -t -A -c "SHOW unix_socket_directories;")
CLIENT_CONNINFO=$("${RUN_PSQL[@]}" -d postgres -c '\conninfo' 2>&1 | tr '\n' ' ' | sed 's/  */ /g')

echo "Pre-flight live server identity: user=${CONNECTED_USER}, server_port=${CONNECTED_SERVER_PORT}, addr=${CONNECTED_SERVER_ADDR}, data_dir=${CONNECTED_DATA_DIR}"
echo "Pre-flight live client conninfo: ${CLIENT_CONNINFO}"

if [[ "${CONNECTED_USER}" != "${USER}" ]]; then
  echo "FATAL SAFETY VIOLATION: Connected user '${CONNECTED_USER}' does not match authorized test user '${USER}'. Aborting." >&2
  exit 1
fi

if [[ "${CONNECTED_SERVER_PORT}" != "${PORT}" ]]; then
  echo "FATAL SAFETY VIOLATION: Connected PostgreSQL server is running on port '${CONNECTED_SERVER_PORT}', mismatching target port '${PORT}'. Aborting." >&2
  exit 1
fi

# Endpoint Identity Safeguard: Validate the exact physical data directory against a fixed allowlist
# Ensures the connected instance is strictly an authorized local disposable test instance.
AUTHORIZED_DISPOSABLE_DATA_DIRS=("/tmp/shadify-disposable-pg" "/tmp/shadify-concurrency-pg")

# Canonicalize connected data directory path to resolve symlinks and path aliases
CANONICAL_CONNECTED_DATA_DIR=""
if command -v realpath >/dev/null 2>&1; then
  CANONICAL_CONNECTED_DATA_DIR="$(realpath "${CONNECTED_DATA_DIR}" 2>/dev/null || echo "${CONNECTED_DATA_DIR}")"
else
  CANONICAL_CONNECTED_DATA_DIR="$(cd "${CONNECTED_DATA_DIR}" 2>/dev/null && pwd -P || echo "${CONNECTED_DATA_DIR}")"
fi

IS_AUTHORIZED_DATA_DIR=0
MATCHED_ALLOWLIST_ENTRY=""
for auth_dir in "${AUTHORIZED_DISPOSABLE_DATA_DIRS[@]}"; do
  CANONICAL_AUTH=""
  if command -v realpath >/dev/null 2>&1; then
    CANONICAL_AUTH="$(realpath "${auth_dir}" 2>/dev/null || echo "${auth_dir}")"
  else
    CANONICAL_AUTH="$(cd "${auth_dir}" 2>/dev/null && pwd -P || echo "${auth_dir}")"
  fi
  if [[ "${CANONICAL_CONNECTED_DATA_DIR}" == "${CANONICAL_AUTH}" ]]; then
    IS_AUTHORIZED_DATA_DIR=1
    MATCHED_ALLOWLIST_ENTRY="${auth_dir}"
    break
  fi
done

if [[ "${IS_AUTHORIZED_DATA_DIR}" -ne 1 ]]; then
  echo "FATAL SAFETY VIOLATION: Connected server data_directory '${CONNECTED_DATA_DIR}' (canonical: '${CANONICAL_CONNECTED_DATA_DIR}') does not match any entry in the fixed disposable allowlist (${AUTHORIZED_DISPOSABLE_DATA_DIRS[*]}). Aborting." >&2
  exit 1
fi
echo "Verified server data directory: '${CANONICAL_CONNECTED_DATA_DIR}' matches authorized allowlist entry '${MATCHED_ALLOWLIST_ENTRY}'"

# Transport & Client Session Effective Endpoint Validation
if [[ "${CONNECTED_SERVER_ADDR}" == "unix_domain_socket" || "${HOST}" == "/"* ]]; then
  # 1. Unix domain socket validation:
  CLIENT_SOCKET_DIR="${HOST}"
  if [[ "${CLIENT_SOCKET_DIR}" != "/"* ]]; then
    CLIENT_SOCKET_DIR="/tmp"
  fi

  # Verify server's configured unix_socket_directories matches client target directory
  if [[ "${CONNECTED_SOCKET_DIR}" != *"${CLIENT_SOCKET_DIR}"* ]]; then
    echo "FATAL SAFETY VIOLATION: Server unix_socket_directories ('${CONNECTED_SOCKET_DIR}') does not match client socket directory ('${CLIENT_SOCKET_DIR}'). Aborting." >&2
    exit 1
  fi

  EXPECTED_SOCKET="${CLIENT_SOCKET_DIR}/.s.PGSQL.${PORT}"
  if [[ ! -S "${EXPECTED_SOCKET}" ]]; then
    echo "FATAL SAFETY VIOLATION: Expected local Unix domain socket '${EXPECTED_SOCKET}' does not exist on filesystem. Aborting." >&2
    exit 1
  fi

  # Verify that the active client session effectively connected via that exact socket
  if [[ "${CLIENT_CONNINFO}" != *"via socket in \"${CLIENT_SOCKET_DIR}\""* ]]; then
    echo "FATAL SAFETY VIOLATION: Client session did not connect via verified socket in '${CLIENT_SOCKET_DIR}'. Conninfo: '${CLIENT_CONNINFO}'. Aborting." >&2
    exit 1
  fi
  echo "Verified client effective endpoint: session actively connected via Unix domain socket in '${CLIENT_SOCKET_DIR}' at port '${PORT}'"
else
  # 2. TCP loopback validation:
  if [[ "${CONNECTED_SERVER_ADDR}" != "127.0.0.1"* && "${CONNECTED_SERVER_ADDR}" != "::1"* ]]; then
    echo "FATAL SAFETY VIOLATION: Connected server address '${CONNECTED_SERVER_ADDR}' is not a local loopback address. Aborting." >&2
    exit 1
  fi
  if [[ "${CLIENT_CONNINFO}" != *"127.0.0.1"* && "${CLIENT_CONNINFO}" != *"::1"* ]]; then
    echo "FATAL SAFETY VIOLATION: Client session did not connect via verified local loopback. Conninfo: '${CLIENT_CONNINFO}'. Aborting." >&2
    exit 1
  fi
  echo "Verified client effective endpoint: session actively connected via TCP loopback at port '${PORT}'"
fi

# Verify target DB name is NEVER a system or protected database
PROTECTED_DBS=("postgres" "template0" "template1" "shadify" "shadify_dev" "shadify_prod" "shadify_production")
for protected in "${PROTECTED_DBS[@]}"; do
  if [[ "${DB}" == "${protected}" ]]; then
    echo "FATAL SAFETY VIOLATION: Target database '${DB}' matches protected name '${protected}'. Aborting." >&2
    exit 1
  fi
done

# If DB already exists, verify its owner in pg_database matches test user before dropping
DB_OWNER=$("${RUN_PSQL[@]}" -d postgres -t -A -c "
  SELECT r.rolname 
  FROM pg_database d 
  JOIN pg_roles r ON d.datdba = r.oid 
  WHERE d.datname = '${DB}';
")

if [[ -n "${DB_OWNER}" && "${DB_OWNER}" != "${USER}" ]]; then
  echo "FATAL SAFETY VIOLATION: Existing database '${DB}' is owned by '${DB_OWNER}', not test user '${USER}'. Refusing to drop. Aborting." >&2
  exit 1
fi

echo "Pre-flight target DB verification passed: target '${DB}' is safe for disposable recreation."

echo "=== Step 1: Recreating clean disposable database: ${DB} on port ${PORT} ==="
"${RUN_PSQL[@]}" -d postgres -c "DROP DATABASE IF EXISTS ${DB};"
"${RUN_PSQL[@]}" -d postgres -c "CREATE DATABASE ${DB} OWNER ${USER};"

echo "=== Step 2: Applying canonical root baseline migration (0_init) ==="
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/../shadify-app/prisma/migrations/0_init/migration.sql"

echo "=== Step 3: Applying test fixture stored procedures and helper functions ==="
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/tests/setup-disposable-schema.sql"

echo "=== Step 4: Applying shadify-api migrations in canonical order ==="
echo "  -> Applying 20261110_000_bootstrap_migration_ledger..."
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/prisma/migrations/20261110_000_bootstrap_migration_ledger/migration.sql"

echo "  -> Applying 20261110_001_create_outbox_events..."
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/prisma/migrations/20261110_001_create_outbox_events/migration.sql"

echo "  -> Applying 20261115_002_security_fencing_and_revocation_ledger..."
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/prisma/migrations/20261115_002_security_fencing_and_revocation_ledger/migration.sql"

echo "  -> Applying 20261115_003_audit_log_and_role_grants..."
"${RUN_PSQL[@]}" -d "${DB}" -f "${DIR}/prisma/migrations/20261115_003_audit_log_and_role_grants/migration.sql"

echo "=== Verification: Checking schema status and tables in ${DB} ==="
"${RUN_PSQL[@]}" -d "${DB}" -c "
  SELECT table_name 
  FROM information_schema.tables 
  WHERE table_schema = 'public' 
  ORDER BY table_name;
"

echo "=== Clean disposable database setup complete with ZERO errors (ON_ERROR_STOP=1 validated) ==="
