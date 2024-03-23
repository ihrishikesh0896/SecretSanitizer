import os
import re

import tomlkit


def apply_rules_to_repo(repo_path, rules):
    for root, dirs, files in os.walk(repo_path, topdown=True):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file_name in files:
            if file_name.startswith('.'):
                continue
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    for rule in rules:
                        regex = re.compile(rule['regex'], re.MULTILINE)
                        for match in regex.finditer(content):
                            # Calculate line number
                            line_start = content.rfind('\n', 0, match.start()) + 1
                            line_end = content.find('\n', match.start(), -1)
                            if line_end == -1:  # If this is the last line in the file
                                line_end = len(content)
                            line_number = content.count('\n', 0, match.start()) + 1
                            print("-------------------------------------")
                            print(f"{match.group(0)} in {match.group(1)}")
                            print(
                                f"Match found for rule | {rule['id']} in {file_path}: {match.group(0)} on line {line_number}")
            except (UnicodeDecodeError, PermissionError) as e:
                print(f"Could not read file {file_path}: {e}")


def load_rules_from_config(config_file):
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = tomlkit.load(f)
        return config_data.get('rules', [])
    except Exception as e:
        print(f"Error reading or parsing config file: {e}")
        return []


config_file = '/Users/hrishikesh/Desktop/github_projects/secret-pusher/configs/regex.toml'

rules = load_rules_from_config(config_file)
repo_path = '/Users/hrishikesh/Desktop/github_projects/dummy-java-project'
apply_rules_to_repo(repo_path, rules)
