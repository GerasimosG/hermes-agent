#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '[state-db-backup] %s\n' "$*" >&2
    exit 1
}

if (( $# != 3 )); then
    fail "Usage: $0 SOURCE_DB DESTINATION_DB MINIMUM_MESSAGE_COUNT"
fi
source_db=$1
destination=$2
minimum_messages=$3
[[ "$minimum_messages" =~ ^[0-9]+$ ]] || fail "Invalid minimum message count"
[[ -f "$source_db" && -s "$source_db" ]] || fail "The source database is missing or empty"
[[ ! "$source_db" -ef "$destination" ]] || fail "Source and destination refer to the same file"
sqlite=$(command -v sqlite3) || fail "sqlite3 is required for a consistent live snapshot"
command -v python3 >/dev/null || fail "python3 is required to verify the candidate"
command -v flock >/dev/null || fail "flock is required to prevent overlapping backups"

parent=$(dirname -- "$destination")
[[ -d "$parent" ]] || fail "The backup destination directory does not exist"
exec 9>"${destination}.backup.lock"
flock -n 9 || fail "Another backup already holds the destination lock"
staging=$(mktemp -d -- "$parent/.sqlite-backup.XXXXXXXX")
trap 'rm -rf -- "$staging"' EXIT
candidate="$staging/state.db"
candidate_sql=${candidate//\'/\'\'}

if ! timeout 3600 "$sqlite" -batch -bail -readonly -cmd '.timeout 5000' \
    "$source_db" "VACUUM INTO '$candidate_sql'"; then
    fail "Consistent SQLite snapshot failed. Previous backup retained"
fi

if ! python3 - "$candidate" "$destination" "$minimum_messages" <<'PY'
import os
from pathlib import Path
import sqlite3
import sys

candidate, destination = map(Path, sys.argv[1:3])
minimum = int(sys.argv[3])
try:
    with sqlite3.connect(candidate.resolve().as_uri() + "?mode=ro", uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("candidate failed SQLite quick_check")
        if db.execute("SELECT COUNT(*) FROM messages").fetchone()[0] < minimum:
            raise ValueError("candidate has fewer messages than the configured minimum")
    for path in (candidate, destination):
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError("a journal sidecar exists beside the candidate or destination")
    with candidate.open("rb") as file:
        os.fsync(file.fileno())
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    previous = candidate.with_name("previous.db")
    try:
        if destination.is_symlink():
            raise ValueError("the backup destination is a symbolic link")
        if destination.exists():
            os.link(destination, previous)
        os.replace(candidate, destination)
        try:
            os.fsync(directory)
        except OSError:
            if previous.exists():
                os.replace(previous, destination)
            else:
                destination.unlink()
            raise
    finally:
        os.close(directory)
except (OSError, ValueError, sqlite3.Error) as exc:
    sys.exit(f"Backup verification or publication failed: {exc}")
PY
then
    fail "Could not complete backup verification and publication"
fi

printf '[state-db-backup] %s backup verified and published (%s bytes)\n' \
    "$(date -Is)" "$(stat -c '%s' -- "$destination")"
