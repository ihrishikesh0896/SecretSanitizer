import re
import uuid
import requests
import git
import sys
import os
from pathlib import Path

# Patterns to identify emails, passwords, and API keys
EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
PASSWORD_REGEX = r"password\s*=\s*['\"]([^'\"]+)['\"]"
API_TOKEN_REGEX = r"api_key\s*=\s*['\"]([^'\"]+)['\"]"
API_KEY_REGEX = r"(apikey\s*=\s*')([^']+)(')"
PRIVATE_KEY_PEM = r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"
PRIVATE_KEY_RSA_REGEX = r"-----BEGIN RSA PRIVATE KEY-----"
PRIVATE_KEY_GENERIC_REGEX = r"-----BEGIN PRIVATE KEY-----"
OAUTH_TOKENS_REGEX = r"[A-Za-z0-9-_]+(\.[A-Za-z0-9-_]+){2,}"
SESSION_IDS_REGEX = r"(session_id|sid|sessionid|token|auth_token)\s*=\s*['\"][A-Za-z0-9+/=]+['\"]"

# Placeholder format
PLACEHOLDER_FORMAT = "SECRET_PLACEHOLDER_{uuid}"
output_mapping_file = 'secrets_mapping.txt'

# scan and replace wrt regex patterns
def scan_and_replace(file_path, output_mapping_file):
    with open(file_path, 'r+', encoding='utf-8') as file:
        content = file.read()
        # Store mappings
        mappings = []
        # Replace emails
        for match in re.findall(EMAIL_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match, placeholder)
            mappings.append((match, placeholder))

        # Replace passwords
        for match in re.finditer(PASSWORD_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Replace API keys
        for match in re.finditer(API_TOKEN_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Replace API Tokens
        for match in re.finditer(API_TOKEN_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))
        
        # Replace PRIVATE_KEY_PEM
        for match in re.finditer(PRIVATE_KEY_PEM, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Replace PRIVATE_KEY_RSA_REGEX
        for match in re.finditer(PRIVATE_KEY_RSA_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))
        
        # Replace PRIVATE_KEY_GENERIC_REGEX
        for match in re.finditer(PRIVATE_KEY_GENERIC_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Replace OAUTH_TOKENS_REGEX
        for match in re.finditer(OAUTH_TOKENS_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Replace SESSION_IDS_REGEX
        for match in re.finditer(SESSION_IDS_REGEX, content):
            placeholder = PLACEHOLDER_FORMAT.format(uuid=uuid.uuid4().hex)
            content = content.replace(match.group(1), placeholder)
            mappings.append((match.group(1), placeholder))

        # Write the modified content back to the file
        file.seek(0)
        file.write(content)
        file.truncate()

    # Write the mappings to the output file
    with open(output_mapping_file, 'a', encoding='utf-8') as mapping_file:
        for original, placeholder in mappings:
            mapping_file.write(f"{original} -> {placeholder}\n")
    return mappings

def process_directory(directory_path, output_mapping_file):
    for path in directory_path.iterdir():
        if path.is_dir() and path.name.startswith('.'):
            continue
        print(f"Processing {path}")
        if path.is_file():  # Adjust the condition based on your requirements
            scan_and_replace(path, output_mapping_file)
        elif path.is_dir():
            process_directory(path, output_mapping_file)  # Recursive call to process subdirectories

workspace_dir = '../../WORKSPACE'
url = []

class GitPackage:
    def __init__(self, url=None):
        if url is None:
            url = []
        self.url = url
        self.repo_name = url.split('/')[-1]
        self.branch_name = 'secrets_removed_' + self.repo_name
        self.repo_path = Path(workspace_dir) / self.repo_name

    def clone_repo(url, workspace_dir):
        repo_name = url.split('/')[-1]
        repo_path = Path(workspace_dir) / repo_name
        if repo_path.exists():
            print(f"Repository already exists at {repo_path}", file=sys.stderr)
        return git.Repo.clone_from(url, repo_path)
    
    def commit_changes(repo_path, branch_name):
        repo = git.Repo(repo_path)
        repo.git.checkout('HEAD', b=branch_name)
        repo.git.add(A=True)
        repo.git.commit(m='Replace secrets with dummy values')
        # Note: Pushing changes might require authentication setup
        repo.git.push('origin', branch_name)


def hex8_4_4_4_12():
    """
    Returns a regex pattern for a generic UUID.
    """
    return r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

def generate_semi_generic_regex(keywords, pattern, case_sensitive=False):
    """
    Generates a semi-generic regex for matching keywords with a specific pattern.
    
    :param keywords: A list of keywords to include in the regex.
    :param pattern: The regex pattern to match after the keywords.
    :param case_sensitive: Whether the regex should be case-sensitive.
    :return: A compiled regex object.
    """
    regex_parts = []
    for keyword in keywords:
        # Escape keyword for regex
        escaped_keyword = re.escape(keyword)
        regex_parts.append(f"{escaped_keyword}\\s*=\\s*\"{pattern}\"")
    regex_str = "|".join(regex_parts)
    if not case_sensitive:
        return re.compile(regex_str, re.IGNORECASE)
    else:
        return re.compile(regex_str)

keywords = [
        "snyk_token",
        "snyk_key",
        "snyk_api_token",
        "snyk_api_key",
        "snyk_oauth_token",
    ]

def scan_directory_for_snyk_tokens(directory_path, regex):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    matches = regex.findall(content)
                    if matches:
                        print(f"Match found in {file_path}: {matches}")
            except (UnicodeDecodeError, PermissionError):
                print(f"Could not read file {file_path}")

def main(urls):
    source_dir = Path(workspace_dir)
    
    # Iterate over files in the directory
    GitPackage(urls)
    print("Secrets replacement completed.")

if __name__ == "__main__":
    main()
    regex = generate_semi_generic_regex(keywords, hex8_4_4_4_12())
    scan_directory_for_snyk_tokens(Path(workspace_dir),regex)