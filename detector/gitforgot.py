#!/usr/bin/env python3
"""Find every recoverable secret in a local Git repository. Exit: 0 clean, 1 findings, 2 error."""
import argparse
import base64
import datetime
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import zlib

DEFAULT_MAX_BLOB = 100 * 1024 * 1024
BINARY_PROBE = 8000
PAIR_WINDOW = 200
MAX_BASE64_RUN = 1024 * 1024
DEFAULT_REFLOG_DAYS = 30
DEFAULT_PRUNE_DAYS = 14

RANK = {"current_tree": 0, "history": 1, "reflog_only": 2, "unreachable": 3}
TYPE_ORDER = {"blob": 0, "commit": 1, "tag": 2}

AWS_KEY_ID = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")
AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")
GITHUB_TOKEN = re.compile(r"(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])")
PRIVATE_KEY = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----")
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
IDENT = re.compile(r"(.*) <(.*)> (\d+) ([+-]\d{4})$")
EXPIRY = re.compile(r"(\d+)[. ]*(second|minute|hour|day|week|month|year)")

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
EXPIRY_DAYS = {"second": 1 / 86400, "minute": 1 / 1440, "hour": 1 / 24, "day": 1,
               "week": 7, "month": 30, "year": 365}
KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}
HISTORY_REASONS = (
    (("HEAD", "refs/heads/", "refs/tags/"), "in the history of"),
    (("refs/original/",), "kept by the filter-branch backup"),
    (("refs/remotes/",), "kept by the remote tracking ref"),
    (("refs/",), "kept by"),
)


class GitError(Exception):
    pass


class Git:
    def __init__(self, repo):
        self.base = ["git", "-C", repo, "--no-replace-objects"]
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")

    def run(self, *args, ok=(0,)):
        proc = subprocess.run(self.base + list(args), env=self.env, capture_output=True)
        if proc.returncode not in ok:
            message = proc.stderr.decode("utf-8", "replace").strip()
            raise GitError(f"git {args[0]} failed: {message}")
        return proc.stdout

    def stream(self, ids, *args):
        proc = subprocess.Popen(self.base + list(args), env=self.env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        def feed():
            try:
                for oid in ids:
                    proc.stdin.write(oid.encode() + b"\n")
                proc.stdin.close()
            except OSError:
                pass

        threading.Thread(target=feed, daemon=True).start()
        return proc


def github_checksum_valid(token):
    crc = zlib.crc32(token[4:34].encode())
    digits = ""
    for _ in range(6):
        digits = BASE62[crc % 62] + digits
        crc //= 62
    return digits == token[34:]


def match_rules(text):
    for m in AWS_KEY_ID.finditer(text):
        nearby = text[max(0, m.start() - PAIR_WINDOW):m.end() + PAIR_WINDOW]
        rule = "aws_key_pair" if AWS_SECRET.search(nearby) else "aws_key_id"
        yield "aws_access_key", rule, m.group(), m.start(), None
    for m in GITHUB_TOKEN.finditer(text):
        yield ("github_classic_token", "ghp_checksum", m.group(), m.start(),
               github_checksum_valid(m.group()))
    for m in PRIVATE_KEY.finditer(text):
        footer = f"-----END {m.group(1)}-----"
        end = text.find(footer, m.end())
        if end == -1:
            yield "private_key", "private_key_header", m.group(), m.start(), None
        else:
            secret = text[m.start():end + len(footer)]
            yield "private_key", "private_key_block", secret, m.start(), None


def decode_base64(run):
    run = run.rstrip("=")
    if len(run) % 4 == 1 or len(run) > MAX_BASE64_RUN:
        return None
    try:
        return base64.b64decode(run + "=" * (-len(run) % 4)).decode("latin-1")
    except ValueError:
        return None


def scan_text(text, encoding=None):
    for match in match_rules(text):
        yield match, encoding
    for run in BASE64_RUN.finditer(text):
        decoded = decode_base64(run.group())
        if decoded is None:
            continue
        label = f"{encoding}+base64" if encoding else "base64"
        for kind, rule, secret, _, checksum in match_rules(decoded):
            yield (kind, rule, secret, run.start(), checksum), label


def notebook_segments(node, in_output=False):
    encoding = "notebook" if in_output else None
    if isinstance(node, str):
        yield node, encoding
    elif isinstance(node, list):
        if node and all(isinstance(item, str) for item in node):
            yield "".join(node), encoding
        else:
            for item in node:
                yield from notebook_segments(item, in_output)
    elif isinstance(node, dict):
        for key, value in node.items():
            if not key.startswith("image/"):
                yield from notebook_segments(value, in_output or key == "outputs")


def parse_notebook(text):
    if not text.lstrip().startswith("{") or '"cells"' not in text:
        return None
    try:
        notebook = json.loads(text)
    except ValueError:
        return None
    return notebook if isinstance(notebook, dict) and "cells" in notebook else None


def scan_blob(text):
    notebook = parse_notebook(text)
    if notebook is None:
        yield from scan_text(text)
        return
    for segment, encoding in notebook_segments(notebook):
        for (kind, rule, secret, _, checksum), label in scan_text(segment, encoding):
            start = max(text.find(secret.split("\n")[0]), 0)
            yield (kind, rule, secret, start, checksum), label


def redact(secret, kind):
    if kind == "private_key":
        return secret.split("\n")[0] + "…"
    return f"{secret[:4]}…{secret[-4:]}"


def list_objects(git):
    out = git.run("cat-file", "--batch-all-objects", "--unordered",
                  "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    for line in out.decode().splitlines():
        oid, kind, size = line.split()
        yield oid, kind, int(size)


def read_objects(git, ids):
    proc = git.stream(ids, "cat-file", "--batch")
    while True:
        header = proc.stdout.readline()
        if not header:
            break
        parts = header.split()
        if len(parts) != 3:
            continue
        data = proc.stdout.read(int(parts[2]))
        proc.stdout.read(1)
        yield parts[0].decode(), parts[1].decode(), data
    proc.wait()


def parse_ident(value):
    m = IDENT.match(value)
    if not m:
        return {"name": None, "email": None, "time": 0, "date": None}
    name, email, seconds, zone = m.groups()
    minutes = int(zone[1:3]) * 60 + int(zone[3:5])
    offset = datetime.timedelta(minutes=-minutes if zone[0] == "-" else minutes)
    moment = datetime.datetime.fromtimestamp(int(seconds), datetime.timezone(offset))
    return {"name": name, "email": email, "time": int(seconds), "date": moment.isoformat()}


def parse_headers(data):
    head, _, message = data.partition(b"\n\n")
    fields = {}
    for line in head.decode("utf-8", "replace").split("\n"):
        key, _, value = line.partition(" ")
        if key:
            fields.setdefault(key, []).append(value)
    return fields, message.decode("utf-8", "replace")


def parse_commit(data):
    fields, message = parse_headers(data)
    author = parse_ident(fields.get("author", [""])[0])
    committer = parse_ident(fields.get("committer", [""])[0])
    return {"parents": fields.get("parent", []), "author": author,
            "time": committer["time"]}, message


def parse_tag(data):
    fields, message = parse_headers(data)
    return {"target": fields.get("object", [None])[0],
            "tagger": parse_ident(fields.get("tagger", [""])[0])}, message


def object_set(git, *revs):
    out = git.run("rev-list", "--objects", "--ignore-missing", *revs)
    return {line.split(b" ", 1)[0].decode() for line in out.splitlines()}


def read_refs(git):
    out = git.run("for-each-ref", "--format=%(objectname) %(*objectname) %(refname)")
    refs = []
    for line in out.decode("utf-8", "replace").splitlines():
        oid, peeled, name = line.split(" ", 2)
        refs.append((name, oid, peeled or oid))
    return refs


def resolve(git, name):
    out = git.run("rev-parse", "-q", "--verify", f"{name}^{{commit}}", ok=(0, 1, 128))
    return out.decode().strip() or None


def read_reflogs(common_dir):
    logs = os.path.join(common_dir, "logs")
    entries = []
    for folder, _, files in os.walk(logs):
        for filename in files:
            path = os.path.join(folder, filename)
            name = os.path.relpath(path, logs).replace(os.sep, "/")
            with open(path, "rb") as handle:
                lines = handle.read().decode("utf-8", "replace").splitlines()
            for index, line in enumerate(reversed(lines)):
                parts = line.split("\t")[0].split(" ")
                if len(parts) >= 4 and parts[-2].isdigit():
                    entries.append((f"{name}@{{{index}}}", parts[1], int(parts[-2])))
    return entries


class Reachability:
    def __init__(self, git, common_dir):
        self.refs = read_refs(git)
        self.head = resolve(git, "HEAD")
        self.orig_head = resolve(git, "ORIG_HEAD")
        self.reflogs = read_reflogs(common_dir)
        extra = [self.orig_head] if self.orig_head else []
        self.history = object_set(git, "--all") | {oid for _, oid, _ in self.refs}
        self.recorded = object_set(git, "--all", "--reflog", *extra)
        self.remote = object_set(git, "--remotes") | {
            oid for name, oid, _ in self.refs if name.startswith("refs/remotes/")}
        self.tree = set()
        if self.head:
            for entry in git.run("ls-tree", "-r", "-z", "HEAD").split(b"\0"):
                fields = entry.split(b"\t", 1)[0].split()
                if len(fields) == 3 and fields[1] == b"blob":
                    self.tree.add(fields[2].decode())

    def label(self, oid):
        if oid in self.tree:
            return "current_tree"
        if oid in self.history:
            return "history"
        if oid in self.recorded:
            return "reflog_only"
        return "unreachable"

    def keepers(self, alive, label):
        if label == "unreachable":
            return [], []
        if label == "reflog_only":
            hits = [(name, when) for name, oid, when in self.reflogs if oid in alive]
            names = [name for name, _ in hits]
            if self.orig_head in alive:
                names.append("ORIG_HEAD")
            return names, [when for _, when in hits]
        names = ["HEAD"] if self.head in alive else []
        names += [name for name, oid, peeled in self.refs if oid in alive or peeled in alive]
        return names, []


def blob_events(git, commits, wanted):
    events = {}
    if not wanted or not commits:
        return events
    proc = git.stream(commits, "diff-tree", "--stdin", "-z", "-r", "-m", "--root",
                      "--no-renames", "--no-abbrev")
    commit = meta = None
    pending = b""
    while True:
        chunk = proc.stdout.read(1 << 16)
        if not chunk:
            break
        tokens = (pending + chunk).split(b"\0")
        pending = tokens.pop()
        for token in tokens:
            if meta is not None:
                _, _, old, new, _ = meta
                path = token.decode("utf-8", "replace")
                for oid in {old, new} & wanted:
                    events.setdefault(oid, []).append((commit, old, new, path))
                meta = None
            elif token.startswith(b":"):
                meta = token.decode().split(" ")
            elif token:
                commit = token.split()[0].decode()
    proc.wait()
    return events


def child_map(commits):
    children = {}
    for oid, commit in commits.items():
        for parent in commit["parents"]:
            children.setdefault(parent, []).append(oid)
    return children


def with_descendants(start, children):
    seen = set()
    todo = list(start)
    while todo:
        oid = todo.pop()
        if oid not in seen:
            seen.add(oid)
            todo.extend(children.get(oid, []))
    return seen


def expiry_days(value, default):
    value = value.strip().lower()
    if not value:
        return default
    if value == "never":
        return None
    if value == "now":
        return 0
    m = EXPIRY.match(value)
    return int(m.group(1)) * EXPIRY_DAYS[m.group(2)] if m else default


def read_expiry(git):
    def setting(key):
        return git.run("config", "--get", key, ok=(0, 1)).decode()
    return (expiry_days(setting("gc.reflogExpireUnreachable"), DEFAULT_REFLOG_DAYS),
            expiry_days(setting("gc.pruneExpire"), DEFAULT_PRUNE_DAYS))


def object_time(common_dir, oid):
    objects = os.path.join(common_dir, "objects")
    try:
        return os.path.getmtime(os.path.join(objects, oid[:2], oid[2:]))
    except OSError:
        packs = glob.glob(os.path.join(objects, "pack", "*.pack"))
        return max(map(os.path.getmtime, packs), default=None)


def estimate_expiry(label, modified, reflog_times, reflog_days, prune_days):
    if label not in ("reflog_only", "unreachable") or prune_days is None or modified is None:
        return None
    when = modified + prune_days * 86400
    if label == "reflog_only":
        if reflog_days is None:
            return None
        when = max([when] + [t + reflog_days * 86400 for t in reflog_times])
    return datetime.datetime.fromtimestamp(when, datetime.timezone.utc).date().isoformat()


def explain(label, names, commit):
    if label == "current_tree":
        return "still present in the HEAD tree"
    if label == "unreachable":
        return "dangling commit not pruned yet" if commit else "orphan object not pruned yet"
    if label == "reflog_only":
        return f"kept only by {names[0] if names else 'a reflog'}"
    for prefixes, reason in HISTORY_REASONS:
        name = next((n for n in names if n.startswith(prefixes)), None)
        if name:
            return f"{reason} {name}"
    return "reachable from a ref"


def build_record(hits, ctx):
    commits, tags, reach, children = ctx["commits"], ctx["tags"], ctx["reach"], ctx["children"]
    time_of = lambda event: commits.get(event[0], {}).get("time", 0)
    chosen = min(hits, key=lambda h: (RANK[reach.label(h["object"])],
                                      TYPE_ORDER[h["object_type"]], h["object"]))
    label = reach.label(chosen["object"])
    blobs = {h["object"] for h in hits if h["object_type"] == "blob"}

    changes = {e for oid in blobs for e in ctx["events"].get(oid, [])}
    added = sorted((e for e in changes if e[2] in blobs and e[1] not in blobs), key=time_of)
    removed = sorted((e for e in changes if e[1] in blobs and e[2] not in blobs), key=time_of)

    alive = with_descendants([e[0] for e in added], children)
    for hit in hits:
        if hit["object_type"] == "commit":
            alive |= with_descendants([hit["object"]], children)
        elif hit["object_type"] == "tag":
            alive.add(hit["object"])

    commit = path = None
    identity = None
    if chosen["object_type"] == "blob":
        own = [e for e in added if e[2] == chosen["object"]] or added
        if own:
            commit, path = own[0][0], own[0][3]
    elif chosen["object_type"] == "commit":
        commit = chosen["object"]
    else:
        commit = tags[chosen["object"]]["target"]
        identity = tags[chosen["object"]]["tagger"]
    if identity is None and commit in commits:
        identity = commits[commit]["author"]

    removed_in = exposure = None
    if commit and label != "current_tree":
        later = with_descendants([commit], children)
        gone = [e for e in removed if e[0] in later]
        if gone:
            removed_in = gone[0][0]
            seconds = commits[removed_in]["time"] - commits[commit]["time"]
            exposure = seconds // 86400

    names, reflog_times = reach.keepers(alive, label)
    pushed = any(h["object"] in reach.remote for h in hits)
    modified = object_time(ctx["common_dir"], chosen["object"])
    return {
        "type": chosen["type"],
        "rule": chosen["rule"],
        "redacted": chosen["redacted"],
        "fingerprint": chosen["fingerprint"],
        "object": chosen["object"],
        "object_type": chosen["object_type"],
        "path": path,
        "line": chosen["line"],
        "commit": commit,
        "author": identity["name"] if identity else None,
        "email": identity["email"] if identity else None,
        "date": identity["date"] if identity else None,
        "reachability": label,
        "refs": names,
        "introduced_in": commit,
        "removed_in": removed_in,
        "exposure_days": exposure,
        "pushed": pushed,
        "encoding": chosen["encoding"],
        "known_example": chosen["known_example"],
        "checksum_valid": chosen["checksum_valid"],
        "recover": f"git cat-file -p {chosen['object']}",
        "occurrences": len({h["object"] for h in hits}),
        "why_alive": explain(label, names, commit),
        "action": "revoke_now" if pushed else "revoke_and_purge",
        "expires_estimate": estimate_expiry(label, modified, reflog_times, *ctx["expiry"]),
    }


def collect_hits(text, oid, object_type, scanner, include_invalid, groups):
    for (kind, rule, secret, start, checksum), encoding in scanner(text):
        if checksum is False and not include_invalid:
            continue
        digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()
        groups.setdefault(f"sha256:{digest}", []).append({
            "type": kind, "rule": rule, "redacted": redact(secret, kind),
            "fingerprint": f"sha256:{digest}", "object": oid, "object_type": object_type,
            "line": text.count("\n", 0, start) + 1, "encoding": encoding,
            "known_example": secret in KNOWN_EXAMPLES, "checksum_valid": checksum,
        })


def scan(repo, max_blob, include_invalid):
    git = Git(repo)
    git_dir = git.run("rev-parse", "--git-common-dir").decode().strip()
    common_dir = os.path.join(repo, git_dir)

    wanted, oversized = [], []
    total = 0
    for oid, kind, size in list_objects(git):
        total += 1
        if kind == "blob" and max_blob and size > max_blob:
            oversized.append((oid, size))
        elif kind in ("blob", "commit", "tag"):
            wanted.append(oid)

    groups, commits, tags = {}, {}, {}
    binary = 0
    for oid, kind, data in read_objects(git, wanted):
        if kind == "commit":
            commits[oid], message = parse_commit(data)
            collect_hits(message, oid, kind, scan_text, include_invalid, groups)
        elif kind == "tag":
            tags[oid], message = parse_tag(data)
            collect_hits(message, oid, kind, scan_text, include_invalid, groups)
        elif b"\0" in data[:BINARY_PROBE]:
            binary += 1
        else:
            text = data.decode("utf-8", "replace")
            collect_hits(text, oid, kind, scan_blob, include_invalid, groups)

    blobs = {h["object"] for hits in groups.values() for h in hits if h["object_type"] == "blob"}
    ctx = {
        "commits": commits, "tags": tags, "common_dir": common_dir,
        "reach": Reachability(git, common_dir), "children": child_map(commits),
        "events": blob_events(git, list(commits), blobs), "expiry": read_expiry(git),
    }
    records = [build_record(hits, ctx) for hits in groups.values()]
    records.sort(key=lambda r: (RANK[r["reachability"]], r["fingerprint"]))

    for oid, size in oversized:
        print(f"skipped {oid}: {size} bytes is over the size limit", file=sys.stderr)
    print(f"scanned {total} objects: {len(records)} secrets, {binary} binary blobs skipped, "
          f"{len(oversized)} blobs over the size limit", file=sys.stderr)
    return records


def main():
    parser = argparse.ArgumentParser(description="Find every recoverable secret in a Git repository.")
    parser.add_argument("repo", help="path to a local repository")
    parser.add_argument("--max-blob-size", type=int, default=DEFAULT_MAX_BLOB, metavar="BYTES",
                        help="skip larger blobs, 0 for no limit (default: 100 MiB)")
    parser.add_argument("--include-invalid", action="store_true",
                        help="also report tokens with a broken checksum")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    try:
        records = scan(args.repo, args.max_blob_size, args.include_invalid)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for record in records:
        print(json.dumps(record, ensure_ascii=False))
    return 1 if records else 0


if __name__ == "__main__":
    sys.exit(main())
