#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
EXPECTED="$ROOT/setup/expected.jsonl"
TARGET="${1:-$ROOT/../leaky-repo}"

rm -rf "$TARGET"
mkdir -p "$TARGET"
cd "$TARGET"
git init -q -b main
git config user.name "Setup Script"
git config user.email "setup@example.test"
: > "$EXPECTED"

as_user() {
  local n="$1" e="$2" d="$3"
  shift 3
  GIT_AUTHOR_NAME="$n" GIT_AUTHOR_EMAIL="$e" GIT_AUTHOR_DATE="$d" \
  GIT_COMMITTER_NAME="$n" GIT_COMMITTER_EMAIL="$e" GIT_COMMITTER_DATE="$d" \
  "$@"
}

fake_secret() {
  local r
  r=$(head -c 512 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  case "$1" in
    aws)
      local u="${r^^}"
      echo "AKIA${u:0:16} ${r:100:40}"
      ;;
    github)
      echo "ghp_${r:200:36}"
      ;;
    privkey)
      local dir
      dir=$(mktemp -d)
      ssh-keygen -t ed25519 -N "" -C "deploy@example.test" -f "$dir/key" -q
      cat "$dir/key"
      rm -rf "$dir"
      ;;
    *)
      echo "unknown type $1" >&2
      exit 1
      ;;
  esac
}

record() {
  local fp
  fp=$(printf '%s' "$3" | sha256sum | cut -d' ' -f1)
  printf '{"scenario":"%s","type":"%s","fingerprint":"%s","expected":"%s"}\n' "$1" "$2" "$fp" "$4" >> "$EXPECTED"
}

echo "# Demo app" > README.md
git add README.md
as_user "Alice Dev" "alice@example.test" "2026-10-01T09:00:00+02:00" git commit -q -m "Initial commit"

s01_present() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$id" "$key" > app.env
  git add app.env
  as_user "Alice Dev" "alice@example.test" "2026-10-01T10:00:00+02:00" git commit -q -m "Add app config"
  record S01 aws "$id" current_tree
}

s02_deleted_file() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$id" "$key" > deploy.env
  git add deploy.env
  as_user "Bob Ops" "bob@example.test" "2026-10-02T10:00:00+02:00" git commit -q -m "Add deploy config"
  git rm -q deploy.env
  as_user "Bob Ops" "bob@example.test" "2026-10-03T10:00:00+02:00" git commit -q -m "Remove deploy config"
  record S02 aws "$id" history
}

s03_amend() {
  local v
  v=$(fake_secret github)
  printf 'token = %s\n' "$v" > settings.ini
  git add settings.ini
  as_user "Carol Dev" "carol@example.test" "2026-10-04T10:00:00+02:00" git commit -q -m "Add settings"
  printf 'token =\n' > settings.ini
  git add settings.ini
  as_user "Carol Dev" "carol@example.test" "2026-10-04T10:05:00+02:00" git commit -q --amend --no-edit
  record S03 github "$v" reflog_only
}

s04_rebase() {
  local v c
  v=$(fake_secret github)
  printf 'ci_token=%s\n' "$v" > ci.cfg
  git add ci.cfg
  as_user "Dan Dev" "dan@example.test" "2026-10-05T10:00:00+02:00" git commit -q -m "Add CI config"
  c=$(git rev-parse HEAD)
  echo "v1" > VERSION
  git add VERSION
  as_user "Dan Dev" "dan@example.test" "2026-10-05T11:00:00+02:00" git commit -q -m "Bump version"
  as_user "Dan Dev" "dan@example.test" "2026-10-05T12:00:00+02:00" git rebase -q --onto "${c}^" "$c"
  record S04 github "$v" reflog_only
}

s05_deleted_branch() {
  local v
  v=$(fake_secret privkey)
  git switch -q -c feature/keys
  printf '%s\n' "$v" > id_deploy
  git add id_deploy
  as_user "Eve Dev" "eve@example.test" "2026-10-06T12:00:00+02:00" git commit -q -m "Add deploy key"
  git switch -q main
  git branch -q -D feature/keys
  record S05 privkey "$v" reflog_only
}

s06_dropped_stash() {
  local v
  v=$(fake_secret github)
  printf 'GITHUB_TOKEN=%s\n' "$v" >> README.md
  as_user "Frank Dev" "frank@example.test" "2026-10-07T10:00:00+02:00" git stash push -q -m "wip"
  git stash drop -q
  record S06 github "$v" unreachable
}

s01_present
s02_deleted_file
s03_amend
s04_rebase
s05_deleted_branch
s06_dropped_stash

echo "Test repo ready at: $TARGET"
echo "Expected findings: $EXPECTED"