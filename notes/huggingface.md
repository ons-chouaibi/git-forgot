# Hugging Face tokens

**Recognize it.** User access tokens start with `hf_`, followed by 34 letters in both upper and lower case, for 37 characters in total. I confirmed this format on tokens I created. In code, look for the variable name `HF_TOKEN`, which the official libraries read automatically.

**Validate it safely.** Only test tokens you own. Make a single read only identity call. Load the token into an environment variable with a hidden prompt, so it never appears in a script or in your shell history:

    read -rs HF_TOKEN && export HF_TOKEN
    curl -s -H "Authorization: Bearer $HF_TOKEN" https://huggingface.co/api/whoami-v2
    unset HF_TOKEN

A `200` with the owner's details means the token is live. My revoked token was rejected with `{"error":"Invalid username or password."}`. Never test a token by pushing a file or accessing a repository.

**What it reveals.** On a live read token I created, the response returned the owner's username, full name and verified email, a stable account ID that survives renames, the organizations the account belongs to, and billing details (plan and payment status). The `auth` object showed the token's name, creation date and role (`read`). Token names often say where a token is used ("colab", "prod"), which points an attacker to other places to look. For fine grained tokens, the response also lists each scoped resource and its permissions, so one call maps exactly what the token can reach. Write access is the main risk: it lets an attacker replace model files that other people download, a supply chain attack.

**Where it leaks, and what to do.** Usually in notebook outputs, `.env` files and Space settings committed by mistake. Clearing a notebook's output or deleting the file doesn't help, because the token stays in Git history. Revoke it in your account settings. Anyone who finds a leaked token can also revoke it, without an account, via `POST /api/credentials/revoke`; the owner is notified by email. That endpoint always returns `202`, so it can't be abused to check whether a token is valid.