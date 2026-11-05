# Results

Score the committed sample with:

```
python evaluation/compare.py evaluation/sample_expected.jsonl evaluation/sample_output.jsonl
```

Result: 15 expected entries (13 secrets, 2 negative controls), 0 wrong, 0 false positives.

## Coverage matrix

| ID | Hidden by | Detector | `git log --all -p` (derived) | `git clone --no-local` | Plain local clone |
|---|---|---|---|---|---|
| S01 | Nothing | current_tree | visible | survives | survives |
| S02 | Deleted file | history | visible | survives | survives |
| S03 | Amend | reflog_only | hidden | gone | survives, unreachable |
| S04 | Rebase | reflog_only | hidden | gone | survives, unreachable |
| S05 | Deleted branch | reflog_only | hidden | gone | survives, unreachable |
| S06 | Dropped stash | unreachable | hidden | gone | survives, unreachable |
| S07 | Staged, never committed | unreachable, no author | hidden | gone | survives, unreachable |
| S08 | filter-branch | history, `refs/original` | visible | gone | survives, unreachable |
| S09 | Pushed, deleted locally | history, `pushed: true` | visible | gone | survives, unreachable |
| S10 | Commit message | history | visible | survives | survives |
| S11 | Tag message | history | hidden | survives | survives |
| S12a | Base64 | history, `encoding: base64` | encoded only | survives | survives |
| S12b | Notebook output | history, `encoding: notebook` | escaped only | survives | survives |
| N01 | Broken checksum | rejected | not applicable | not reported | not reported |
| N02 | Binary blob | skipped, known blind spot | not applicable | not reported | not reported |

S10, S11 and S12 are light versions: one small case per detector feature, using GitHub, AWS and private key secrets. There is no Hugging Face rule.

## Three runs

| Run | Secrets found | Result |
|---|---|---|
| Before gc | 13 | All labels correct |
| After plain `git gc` (S13) | 13 | Every field identical to the run before gc |
| After full purge (S14) | 0 | Exit code 0; 21 objects left |

The purge does not reach N02: its token is still in a binary blob, which the detector skips. Zero findings means nothing was found in what is scanned.

## Most surprising row

S07. The secret was only ever staged, so no commit, branch or reflog points to it and `git log --all` cannot show it, yet the whole file is still in the object database.

A close second is the clone comparison: a real clone keeps 6 of 13 secrets, while a plain local-path clone keeps all 13 because it copies the whole object store.

## How each number was obtained

- **Before gc and the sample files:** a real run of the final detector and setup script.
- **After gc:** a real run of the final detector, on an earlier build of the same test repo with different random secrets.
- **Purge, clones and read-only proof:** measured on a scratch repo before the detector's comment cleanup, which did not change its logic. `.git` was byte-identical after a scan, and none of the 24 planted strings appeared in the output.
- **`git log --all -p` column:** derived from each object's reachability and type, not from a separate measured run.

## Not done

- Open source scanner column
- Scale test on a large repository
- CI workflow
