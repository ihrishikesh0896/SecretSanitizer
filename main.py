import argparse
import shutil
import sys
from pathlib import Path

import git
import tomlkit

from src.apply_rules import *

# Configuration for secret patterns and their placeholders
SECRET_PATTERNS = {
    "EMAIL_REGEX": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PASSWORD_REGEX": r"password\s*=\s*['\"]([^'\"]+)['\"]",
    "API_TOKEN_REGEX": r"api_key\s*=\s*['\"]([^'\"]+)['\"]",
    "API_KEY_REGEX": r"(apikey\s*=\s*')([^']+)(')",
    "PRIVATE_KEY_PEM": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "PRIVATE_KEY_RSA_REGEX": r"-----BEGIN RSA PRIVATE KEY-----",
    "PRIVATE_KEY_GENERIC_REGEX": r"-----BEGIN PRIVATE KEY-----",
    "OAUTH_TOKENS_REGEX": r"[A-Za-z0-9-_]+(\.[A-Za-z0-9-_]+){2,}",
    "SESSION_IDS_REGEX": r"(session_id|sid|sessionid|token|auth_token)\s*=\s*['\"][A-Za-z0-9+/=]+['\"]",
}

PLACEHOLDER_FORMAT = "SECRET_PLACEHOLDER_{uuid}"
OUTPUT_MAPPING_FILE = 'secrets_mapping.txt'


class SecretScannerInhouse:
    def __init__(self, patterns, placeholder_format, output_mapping_file):
        self.patterns = patterns
        self.placeholder_format = placeholder_format
        self.output_mapping_file = output_mapping_file

    def scan_and_replace(self, file_path):
        with open(file_path, 'r+', encoding='utf-8') as file:
            content = file.read()
            mappings = []

            for pattern_name, pattern in self.patterns.items():
                for match in re.finditer(pattern, content):
                    placeholder = self.placeholder_format.format(uuid=uuid.uuid4().hex)
                    content = re.sub(match.group(0), placeholder, content)
                    mappings.append((match.group(0), placeholder))

            file.seek(0)
            file.write(content)
            file.truncate()

        with open(self.output_mapping_file, 'a', encoding='utf-8') as mapping_file:
            for original, placeholder in mappings:
                mapping_file.write(f"{original} -> {placeholder}\n")

        return mappings

    @staticmethod
    def process_directory(directory_path, scanner):
        for path in Path(directory_path).iterdir():
            if path.is_dir() and path.name.startswith('.'):
                continue
            logging.info(f"Processing {path}")
            if path.is_file():
                scanner.scan_and_replace(path)
            elif path.is_dir():
                SecretScannerInhouse.process_directory(path, scanner)


class GitPackage:
    def __init__(self, url, workspace_dir):
        self.url = url
        self.repo_name = url.split('/')[-1].replace('.git', '')
        self.repo_path = Path(workspace_dir) / self.repo_name
        if os.path.exists(self.repo_path):
            shutil.rmtree(self.repo_path)

    def repository_path(self):
        return self.repo_path

    def clone_repo(self):
        if self.repo_path.exists():
            logging.error(f"Repository already exists at {self.repo_path}")
            return None
        return git.Repo.clone_from(self.url, self.repo_path)

    def get_next_branch_name(self, base_name='test_fixed_creds'):
        repo = git.Repo(self.repo_path)
        branches = [branch.name for branch in repo.branches]
        branch_numbers = [int(name.split('-')[-1]) for name in branches if
                          name.startswith(base_name) and name.split('-')[-1].isdigit()]
        next_number = max(branch_numbers + [0]) + 1
        return f"{base_name}-{next_number}"

    def commit_changes(self):
        repo = git.Repo(self.repo_path)
        # Check if there are changes to commit
        if repo.is_dirty(untracked_files=True):
            new_branch_name = self.get_next_branch_name()
            repo.git.checkout('HEAD', b=new_branch_name)
            repo.git.add(A=True)  # Stages all changes, including untracked files
            repo.git.commit(m='Replace secrets with placeholder values')
            repo.git.push('origin', new_branch_name)
        else:
            logging.info("No changes to commit, working tree clean.")


def main(urls, workspace_dir, action_mode):
    logging.basicConfig(level=logging.INFO)
    for url in urls:
        git_package = GitPackage(url, workspace_dir)
        git_package.clone_repo()
        repository_path = git_package.repository_path()

        # Ensure action_mode is properly passed and used in the script
        rules = load_rules_from_config(config_file)
        apply_rules_to_repo(workspace_dir, rules, repository_path, action_mode)

        if action_mode == 'update':
            git_package.commit_changes()

        logging.info(f"Process completed for repository: {url}")
        logging.info("---------------------------------------------------------------")



config_file = '/Users/hrishikesh/Desktop/github_projects/secret-pusher/configs/regex.toml'


def load_rules_from_config(config_file):
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = tomlkit.load(f)
        return config_data.get('rules', [])
    except Exception as e:
        print(f"Error reading or parsing config file: {e}")
        return []


def display_usage():
    print("Usage: python main.py -urls <git url> -workspace-dir </path/to/repository> -action_mode <mode>")
    print("-workspace-dir: Path to the repository where rules will be applied.")
    print("-urls: Input URLs not supplied")
    print("-action_mode: 'update' to replace secrets and commit changes, 'log' to only log the findings")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan and replace secrets in git repositories.")
    parser.add_argument('-urls', type=lambda s: s.split(','), help='URL(s) of the git repositories to process - comma-separated values [ex: url1,url2,...]')
    parser.add_argument('-workspace_dir', type=str, default='../WORKSPACE', help='Directory where repositories will be cloned and processed.')
    parser.add_argument('-action_mode', type=str, choices=['update', 'log'], default='log', help='Mode of operation: "update" to modify files, "log" to only log findings')

    args = parser.parse_args()
    urls = args.urls
    workspace_dir = args.workspace_dir
    action_mode = args.action_mode
    main(urls, workspace_dir, action_mode)