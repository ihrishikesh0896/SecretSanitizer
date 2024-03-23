import os
import re


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
                        matches = regex.findall(content)
                        if matches:
                            print(f"Match found for rule | {rule['id']} in {file_path}: {matches}")
            except (UnicodeDecodeError, PermissionError) as e:
                print(f"Could not read file {file_path}: {e}")
