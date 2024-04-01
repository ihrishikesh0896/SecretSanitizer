import csv
import logging
import os
import re
import uuid


def generate_placeholder():
    return f"uuid_{uuid.uuid4().hex}"


def replace_secrets(repository_path, file_path, content, rules):
    updated_content = content
    log_data = []
    # Define the CSV file path in the root of the repository
    csv_file_path = os.path.join(repository_path, 'secrets_replacement_log.csv')

    for rule in rules:
        regex = re.compile(rule['regex'], re.MULTILINE)
        matches = list(regex.finditer(content))
        for match in matches:
            print(match, {rule['id']})
            placeholder = generate_placeholder()
            secret_value = match.group(1)
            line_number = content.count('\n', 0, match.start()) + 1

            logging.info(f"Match found for rule | {rule['id']} in {file_path} on line {line_number}")
            updated_content = updated_content.replace(secret_value, placeholder, 1)  # Replace once per match

            logging.info(f"Replaced secret in {file_path} with {placeholder} on line {line_number}")

            # Add the log data to the list
            log_data.append({
                'filepath': file_path,
                'line_number': line_number,
                'secret_value': secret_value,
                'replaced_value': placeholder
            })

    # Write log data to a CSV file at the end of the process
    with open(csv_file_path, 'a', newline='') as csvfile:
        fieldnames = ['filepath', 'line_number', 'secret_value', 'replaced_value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Only write the header if the file is new
        if csvfile.tell() == 0:
            writer.writeheader()

        writer.writerows(log_data)
    # logging.info(f"Mapping file @ {str(csv_file_path)}")
    return updated_content


def apply_rules_to_repo(repo_path, rules, repository_path):
    repo_root = repo_path  # Assuming repo_path is the root directory of the repository
    for root, dirs, files in os.walk(repository_path, topdown=True):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file_name in files:
            if file_name.startswith('.') or file_name.endswith('.ipynb'):
                continue
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                updated_content = replace_secrets(repository_path, file_path, content, rules)

                if content != updated_content:
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write(updated_content)

            except (UnicodeDecodeError, PermissionError) as e:
                logging.error(f"Could not read file {file_path}: {e}")


if __name__ == '__main__':
    repo_path = os.getcwd()  # Gets the current working directory, assuming the script is run from the root
    rules = [{'regex': r'sensitive_regex_pattern', 'id': 'example_rule_id'}]
    apply_rules_to_repo(repository_path, rules)
