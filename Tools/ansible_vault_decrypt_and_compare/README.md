# ansible_vault_decrypt_and_compare

## Config

- `Configuration:` Vault path must be provided i.e.:

```bash

vault-check-decrypt.py path/to/vault --branch label/XX-1234-name-of-branch # [Or leave `--branch` empty to compare with main]

```

`GITLAB_VAULT_CHECK_TOKEN` - local env must be set before running

```bash

export GITLAB_VAULT_CHECK_TOKEN=glpat-dGHGaQM-8pG6Yxxx123

```

`--branch` tag is optional

### Description

- `Vault Decryption:` Decrypt the Vault using the password file, also specified for `vault-pass.py` in the repo's root directory
- `GitLab Integration:` Checks if API key is valid and proceeds if so, otherwise throws an exception.
- `Content Comparison:` Compares the decrypted contents of the Vault file from the current and target [main] branches, highlighting differences
- `Error Handling:` Catches and reports errors that may occur during file operations, connection, decryption

### Requirements

Depends on the common package

```bash

(.venv) $ python3 -m pip install -r bin/requirements.txt

```
