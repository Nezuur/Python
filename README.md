# Python

Python programs and tools for various purposes.

- [Python](#python)
  - [Tools/ansible\_vault\_decrypt\_and\_compare](#toolsansible_vault_decrypt_and_compare)

## Tools/ansible_vault_decrypt_and_compare

The `vault-check-decrypt.py` script is designed to decrypt and compare Ansible Vault files between the current local branch and a specified branch in a GitLab repository.

It connects to GitLab to retrieve the encrypted file from the target branch, decrypts both the local and remote files using a password read from a specified file, and then uses a diff utility to highlight differences between the contents of the two decrypted files.
This tool is useful for ensuring consistency and integrity across different versions of Ansible Vault files.
