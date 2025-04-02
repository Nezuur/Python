#!/usr/bin/env python3

"""
This script decrypts and compares Ansible Vault files between
the current local branch and a specified branch in a GitLab repository
"""

import os
import difflib
import argparse
import binascii
import subprocess
from urllib.parse import urlparse
import gitlab
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

GITLAB_URL = "https://gitlab.com"
GITLAB_TOKEN = os.environ.get('GITLAB_VAULT_CHECK_TOKEN')
VAULT_PASSWORD_FILE = "./vault-pass.txt"

class VaultManager:
    """Manages Ansible Vault decryption and comparison with GitLab."""

    def __init__(self, vault_path, gl):
        self.vault_path = vault_path
        self.password = self.read_password_file()
        self.gl = gl
        self.project = self.get_project_from_git_dir()

    def get_project_from_git_dir(self):
        """Retrieve the GitLab project from the current git directory."""
        try:
            remote_url = subprocess.check_output(
                ['git', 'config', '--get', 'remote.origin.url'],
                text=True
            ).strip()
            path = urlparse(remote_url).path.strip('/').rstrip('.git')
            return self.gl.projects.get(path)
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Error: Unable to retrieve the Git remote URL") from e
        except gitlab.exceptions.GitlabGetError as e:
            raise ValueError("Error: GitLab project not found for the current repository") from e

    def read_password_file(self):
        """Read the vault password from a file."""
        if os.path.isfile(VAULT_PASSWORD_FILE):
            with open(VAULT_PASSWORD_FILE, 'r', encoding='utf-8') as file:
                return file.read().strip()
        raise FileNotFoundError("Password file not found.")

    def get_file_from_gitlab(self, vault_path, branch):
        """Get the encrypted vault file from GitLab."""
        file_data = self.project.files.raw(file_path=vault_path, ref=branch)
        return file_data.decode("utf-8").strip()

    def decrypt_ansible_vault(self, vault_content):
        """Decrypt the content of an Ansible Vault file."""

        password = self.password.encode()
        lines = vault_content.splitlines()
        outer_hex = "".join(lines[1:])
        outer_bytes = binascii.unhexlify(outer_hex)
        parts = outer_bytes.split(b'\n')

        if len(parts) < 3:
            raise ValueError("Invalid vault format.")

        hex_salt, hex_hmac, hex_ciphertext = parts[0:3]
        salt = binascii.unhexlify(hex_salt)
        hmac_from_file = binascii.unhexlify(hex_hmac)
        ciphertext = binascii.unhexlify(hex_ciphertext)

        # Key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=80,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        derived_keys = kdf.derive(password)
        aes_key = derived_keys[:32]
        hmac_key = derived_keys[32:64]
        iv = derived_keys[64:80]

        # HMAC verification
        hmac_calculator = HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        hmac_calculator.update(ciphertext)
        calculated_hmac = hmac_calculator.finalize()

        if calculated_hmac != hmac_from_file:
            raise ValueError("HMAC verification failed.")

        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode("utf-8")

    def compare_contents(self, content1, content2, branch_name):
        """Compare the decrypted contents and print the differences."""
        diff = difflib.unified_diff(
            content1.splitlines(),
            content2.splitlines(),
            fromfile='current branch',
            tofile=branch_name,
            lineterm=''
        )

        for line in diff:
            if line.startswith('-'):
                print('\033[91m' + line + '\033[0m')
            elif line.startswith('+'):
                print('\033[92m' + line + '\033[0m')
            else:
                print(line)

    def run_comparison(self, branch):
        """Run the comparison between the local and specified branch."""

        try:
            main_encrypted = self.get_file_from_gitlab(self.vault_path, branch)
            main_content = self.decrypt_ansible_vault(main_encrypted)

            with open(self.vault_path, 'r', encoding='utf-8') as current_file:
                current_content = self.decrypt_ansible_vault(current_file.read())

            self.compare_contents(main_content, current_content, branch)

        except FileNotFoundError as e:
            print(f"Error while getting file from GitLab: {e}")
        except ValueError as e:
            print(f"Error while decrypting vault: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

def parse_arguments():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description='Decrypt and compare Ansible Vault files in current and target branches'
    )
    parser.add_argument('vault_path', type=str, help='Path to the Vault file')
    parser.add_argument('--branch', type=str, help='Branch to compare against', default='main')
    return parser.parse_args()

def main():
    """Main function to execute the script."""

    args = parse_arguments()

    if not GITLAB_TOKEN:
        raise Exception("Error: GitLab token is not set, set the env variable GITLAB_VAULT_CHECK_TOKEN.")

    try:
        gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_TOKEN)
        gl.auth()
        print("GitLab authentication successful.")
    except Exception as e:
        raise Exception("Error: Invalid GitLab token") from e

    vault_manager = VaultManager(args.vault_path, gl)
    vault_manager.run_comparison(args.branch)

if __name__ == '__main__':
    main()
