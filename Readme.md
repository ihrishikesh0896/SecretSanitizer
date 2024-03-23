# SecretSanitizer

Secret Pusher is a tool designed to identify and replace sensitive information, such as passwords, API keys, and other
secrets, in your codebase with placeholders. This helps in preventing the accidental push of sensitive data into version
control systems. Secret Pusher scans your repositories, replaces secrets with unique placeholders, and logs the changes
for audit and reversal purposes.

## Features

- **Comprehensive Secret Detection**: Utilizes regular expressions to identify various types of secrets, including
  passwords, API keys, private keys, and more.
- **Automated Secret Replacement**: Automatically replaces detected secrets with unique, generated placeholders.
- **Support for Multiple Repositories**: Can process multiple git repositories in a single run.
- **Audit Logging**: Generates a log of all replaced secrets and their locations for tracking and reversal if necessary.
- **Customizable Secret Patterns**: Allows for the addition of custom secret detection patterns via configuration.

## Installation

To use Secret Pusher, you need to have Python installed on your system. Clone the repository from GitHub and install the
required dependencies:

```bash
git clone https://github.com/yourusername/secret-pusher.git
cd secret-pusher
pip install -r requirements.txt
```

## Usage

Navigate to the Secret Pusher directory and run the script with the necessary arguments:

```bash
python secret_pusher.py -urls [URLs of the git repositories] -workspace-dir [Path to the directory where repositories will be cloned]
```

### Arguments

- `-urls`: A list of URLs of the git repositories to scan and replace secrets.
- `-workspace-dir`: The directory where the repositories will be cloned and processed.

### Example

```bash
python secret_pusher.py -urls https://github.com/user/repo1.git,https://github.com/user/repo2.git -workspace-dir /path/to/workspace
```

## Configuration

Secret patterns are defined in a configuration file (`configs/regex.toml`). You can customize this file to add or modify
the regular expressions used for detecting secrets.

Example configuration:

```toml
[[rules]]
id = "API_KEY"
regex = '''(apikey\s*=\s*['"])([^'"]+)(['"])'''
```

## Contributing

We welcome contributions to Secret Pusher! If you have suggestions for improvements or bug fixes, please open an issue
or submit a pull request.

## License

Secret Pusher is released under the [MIT License](LICENSE).

---

For more information, please visit
the [Secret Pusher GitHub repository](https://github.com/ihrishikesh0896/secret-pusher).