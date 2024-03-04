import re
import os

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
                            print(f"Match found for rule | {rule['id']} in {file_path}: {match.group(0)} on line {line_number}")
            except (UnicodeDecodeError, PermissionError) as e:
                print(f"Could not read file {file_path}: {e}")

if __name__ == '__main__':
    apply_rules_to_repo(repo_path, rules)