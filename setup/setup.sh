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
git config core.autocrlf false
: > "$EXPECTED"

# Dates stay relative so reflog entries remain inside the 30 day gc window.
days_ago() {
  date -u -d "$1 days ago" "+%Y-%m-%dT$2:00+02:00"
}

as_user() {
  local n="$1" e="$2" d="$3"
  shift 3
  GIT_AUTHOR_NAME="$n" GIT_AUTHOR_EMAIL="$e" GIT_AUTHOR_DATE="$d" \
  GIT_COMMITTER_NAME="$n" GIT_COMMITTER_EMAIL="$e" GIT_COMMITTER_DATE="$d" \
  "$@"
}

# CRC32 of the token body in 6 base62 digits. The gzip trailer holds the CRC32.
github_checksum() {
  local alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  local crc out="" i
  crc=$(printf '%s' "$1" | gzip -c | tail -c 8 | od -An -tu4 -N4 | tr -d ' ')
  for i in 1 2 3 4 5 6; do
    out="${alphabet:crc%62:1}$out"
    crc=$((crc / 62))
  done
  echo "$out"
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
      local body="${r:200:30}"
      echo "ghp_${body}$(github_checksum "$body")"
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
as_user "Alice Dev" "alice@example.test" "$(days_ago 25 09:00)" git commit -q -m "Initial commit"

s01_present() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$id" "$key" > app.env
  git add app.env
  as_user "Alice Dev" "alice@example.test" "$(days_ago 25 10:00)" git commit -q -m "Add app config"
  record S01 aws "$id" current_tree
}

s02_deleted_file() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$id" "$key" > deploy.env
  git add deploy.env
  as_user "Bob Ops" "bob@example.test" "$(days_ago 24 10:00)" git commit -q -m "Add deploy config"
  git rm -q deploy.env
  as_user "Bob Ops" "bob@example.test" "$(days_ago 23 10:00)" git commit -q -m "Remove deploy config"
  record S02 aws "$id" history
}

s03_amend() {
  local v
  v=$(fake_secret github)
  printf 'token = %s\n' "$v" > settings.ini
  git add settings.ini
  as_user "Carol Dev" "carol@example.test" "$(days_ago 22 10:00)" git commit -q -m "Add settings"
  printf 'token =\n' > settings.ini
  git add settings.ini
  as_user "Carol Dev" "carol@example.test" "$(days_ago 22 10:05)" git commit -q --amend --no-edit
  record S03 github "$v" reflog_only
}

s04_rebase() {
  local v c
  v=$(fake_secret github)
  printf 'ci_token=%s\n' "$v" > ci.cfg
  git add ci.cfg
  as_user "Dan Dev" "dan@example.test" "$(days_ago 21 10:00)" git commit -q -m "Add CI config"
  c=$(git rev-parse HEAD)
  echo "v1" > VERSION
  git add VERSION
  as_user "Dan Dev" "dan@example.test" "$(days_ago 21 11:00)" git commit -q -m "Bump version"
  as_user "Dan Dev" "dan@example.test" "$(days_ago 21 12:00)" git rebase -q --onto "${c}^" "$c"
  record S04 github "$v" reflog_only
}

s05_deleted_branch() {
  local v
  v=$(fake_secret privkey)
  git switch -q -c feature/keys
  printf '%s\n' "$v" > id_deploy
  git add id_deploy
  as_user "Eve Dev" "eve@example.test" "$(days_ago 20 12:00)" git commit -q -m "Add deploy key"
  git switch -q main
  git branch -q -D feature/keys
  record S05 privkey "$v" reflog_only
}

s06_dropped_stash() {
  local v
  v=$(fake_secret github)
  printf 'GITHUB_TOKEN=%s\n' "$v" >> README.md
  as_user "Frank Dev" "frank@example.test" "$(days_ago 19 10:00)" git stash push -q -m "wip"
  git stash drop -q
  record S06 github "$v" unreachable
}

record_pushed() {
  local fp
  fp=$(printf '%s' "$3" | sha256sum | cut -d' ' -f1)
  printf '{"scenario":"%s","type":"%s","fingerprint":"%s","expected":"%s","pushed":true}\n' "$1" "$2" "$fp" "$4" >> "$EXPECTED"
}

s07_staged_only() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$id" "$key" > staged.env
  git add staged.env
  git reset -q -- staged.env
  rm staged.env
  record S07 aws "$id" unreachable
}

s08_filter_branch() {
  local v
  v=$(fake_secret privkey)
  printf '%s\n' "$v" > id_backup
  git add id_backup
  as_user "Grace Ops" "grace@example.test" "$(days_ago 18 10:00)" git commit -q -m "Add backup key"
  as_user "Grace Ops" "grace@example.test" "$(days_ago 18 11:00)" \
    env FILTER_BRANCH_SQUELCH_WARNING=1 \
    git filter-branch --prune-empty --index-filter 'git rm -q --cached --ignore-unmatch id_backup' -- main > /dev/null
  record S08 privkey "$v" history
}

# Orphan branch: pushing from main would also mark S01 and S02 as pushed.
s09_pushed() {
  local v remote
  v=$(fake_secret github)
  remote="$PWD-remote.git"
  rm -rf "$remote"
  git init -q --bare "$remote"
  git remote add origin "$remote"
  git switch -q --orphan release/ci
  printf 'deploy_token=%s\n' "$v" > release.cfg
  git add release.cfg
  as_user "Heidi Ops" "heidi@example.test" "$(days_ago 17 10:00)" git commit -q -m "Add release config"
  git push -q origin release/ci
  git switch -q main
  git branch -q -D release/ci
  record_pushed S09 github "$v" history
}

# Negative control: a token with a broken checksum must not be reported.
n01_broken_checksum() {
  local v
  v=$(fake_secret github)
  if [ "${v: -1}" = "0" ]; then
    v="${v%?}1"
  else
    v="${v%?}0"
  fi
  printf 'legacy_token=%s\n' "$v" > legacy.cfg
  git add legacy.cfg
  as_user "Ivan Dev" "ivan@example.test" "$(days_ago 16 10:00)" git commit -q -m "Add legacy config"
  record N01 github "$v" none
}

# Light scenarios: one small case per detector feature.
s10_commit_message() {
  local v
  v=$(fake_secret github)
  echo "v2" > VERSION
  git add VERSION
  as_user "Judy Dev" "judy@example.test" "$(days_ago 15 10:00)" git commit -q -m "Bump version again" -m "release token: $v"
  record S10 github "$v" history
}

s11_annotated_tag() {
  local id key
  read -r id key <<< "$(fake_secret aws)"
  as_user "Kim Ops" "kim@example.test" "$(days_ago 14 10:00)" \
    git tag -a v1 -m "$(printf 'Release notes\n\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s' "$id" "$key")"
  record S11 aws "$id" history
}

s12a_base64() {
  local v
  v=$(fake_secret github)
  printf 'encoded_token: %s\n' "$(printf '%s' "$v" | base64 -w0)" > encoded.yml
  git add encoded.yml
  as_user "Leo Dev" "leo@example.test" "$(days_ago 13 10:00)" git commit -q -m "Add encoded config"
  git rm -q encoded.yml
  as_user "Leo Dev" "leo@example.test" "$(days_ago 12 10:00)" git commit -q -m "Remove encoded config"
  record S12a github "$v" history
}

s12b_notebook() {
  local v
  v=$(fake_secret privkey)
  printf '{"cells":[{"cell_type":"code","source":["print(key)"],"outputs":[{"output_type":"stream","name":"stdout","text":["%s\\n"]}]}],"nbformat":4,"nbformat_minor":5}\n' "${v//$'\n'/\\n}" > analysis.ipynb
  git add analysis.ipynb
  as_user "Mia Dev" "mia@example.test" "$(days_ago 11 10:00)" git commit -q -m "Add analysis notebook"
  git rm -q analysis.ipynb
  as_user "Mia Dev" "mia@example.test" "$(days_ago 10 10:00)" git commit -q -m "Remove analysis notebook"
  record S12b privkey "$v" history
}

# Negative control: binary blobs are skipped, so this token must not be reported.
n02_binary_blob() {
  local v
  v=$(fake_secret github)
  printf 'BIN\0%s\n' "$v" > asset.bin
  git add asset.bin
  as_user "Nick Dev" "nick@example.test" "$(days_ago 9 10:00)" git commit -q -m "Add binary asset"
  record N02 github "$v" none
}

s01_present
s02_deleted_file
s03_amend
s04_rebase
s05_deleted_branch
s06_dropped_stash
s07_staged_only
s08_filter_branch
s09_pushed
n01_broken_checksum
s10_commit_message
s11_annotated_tag
s12a_base64
s12b_notebook
n02_binary_blob

echo "Test repo ready at: $TARGET"
echo "Expected findings: $EXPECTED"