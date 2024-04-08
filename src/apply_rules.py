import csv
import logging
import os
import re
import uuid


def generate_placeholder():
    return f"uuid_{uuid.uuid4().hex}"


def replace_secrets(repository_path, file_path, content, rules, action_mode):
    updated_content = content
    log_data = []
    csv_file_path = os.path.join(repository_path, 'secrets_replacement_log.csv')

    for rule in rules:
        regex = re.compile(rule['regex'], re.MULTILINE)
        matches = list(regex.finditer(content))
        try:
            for match in matches:
                placeholder = generate_placeholder()
                secret_value = match.group(1)
                line_number = content.count('\n', 0, match.start()) + 1

                logging.critical(f"Match found for rule | {rule['id']} in {file_path} on line {line_number}")
                if action_mode == 'update':
                    updated_content = updated_content.replace(secret_value, placeholder, 1)
                    logging.critical(f"Replaced secret in {file_path} with {placeholder} on line {line_number}")

                log_data.append({
                    'filepath': file_path,
                    'line_number': line_number,
                    'secret_value': secret_value,
                    'replaced_value': placeholder if action_mode == 'update' else 'Not replaced'
                })
        except Exception as e:
            logging.critical(f"{e} | Rule match error | in {file_path} on line {line_number}")

    with open(csv_file_path, 'a', newline='') as csvfile:
        fieldnames = ['filepath', 'line_number', 'secret_value', 'replaced_value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:
            writer.writeheader()

        writer.writerows(log_data)

    return updated_content


def apply_rules_to_repo(repo_path, rules, repository_path, action_mode):
    for root, dirs, files in os.walk(repo_path, topdown=True):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file_name in files:
            if file_name.startswith('.') or file_name.endswith('.ipynb'):
                continue
            file_path = os.path.join(root, file_name)
            logging.info('Searching file: {}'.format(file_path))
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                updated_content = replace_secrets(repository_path, file_path, content, rules, action_mode)

                if action_mode == 'update' and content != updated_content:
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write(updated_content)

            except (UnicodeDecodeError, PermissionError) as e:
                logging.error(f"Could not read file {file_path}: {e}")


if __name__ == '__main__':
    repo_path = os.getcwd()
    rules = [{'regex': r'sensitive_regex_pattern', 'id': 'example_rule_id'}]
    action_mode = 'log'  # Can be 'update' or 'log'
    apply_rules_to_repo(repo_path, rules, action_mode)
