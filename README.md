# What Git forgot to forget

A secret that was only staged, never committed, stays whole in `.git`. `git log --all` can't show it, yet `git cat-file` prints it. This tool finds every secret a local repository can still give back: 13 of 13 planted, 0 false positives.

## Why deleted data survives

Deleting, amending or rebasing only moves refs; the old objects stay. `git gc` removes them once they are unreachable and old enough: by default 30 days for unreachable reflog entries and 2 weeks for unreachable objects.

## Run

```
bash setup/setup.sh
python detector/gitforgot.py ../leaky-repo > out.jsonl
python evaluation/compare.py setup/expected.jsonl out.jsonl
```

Output is JSON Lines. Exit codes: 0 clean, 1 findings, 2 error. On Windows, redirect from Git Bash, not PowerShell 5.1.

## Coverage

| Hidden by | Reported as | Real clone |
|---|---|---|
| Nothing | current_tree | survives |
| Deleted file, commit message, tag, base64, notebook | history | survives |
| filter-branch, pushed then deleted | history | gone |
| Amend, rebase, deleted branch | reflog_only | gone |
| Dropped stash, staged only | unreachable | gone |

Labels hold after `git gc`, and a full purge leaves 0 findings. A plain local-path clone keeps all 13 secrets. Full matrix: [evaluation/results.md](evaluation/results.md).

## Limits

Not covered: the remote side, pruned objects, history missing from shallow or partial clones, Git LFS content, binary blobs, blobs over 100 MiB by default, secrets split across lines, and tokens in `.git/config`. Known public examples are flagged, not filtered.

## How to really forget

```
git filter-branch --index-filter 'git rm --cached --ignore-unmatch FILE' -- --all
git for-each-ref --format='%(refname)' refs/original | xargs -n1 git update-ref -d
git reflog expire --expire=now --expire-unreachable=now --all
git gc --prune=now
```

This only cleans your copy. Once pushed, revoking the secret is the only real fix.

## Credential note

The Hugging Face token note is in [notes/huggingface.md](notes/huggingface.md).

