# Example Python script with hardcoded sensitive information

# Hardcoded email and password (not secure!)
email = "user@example.com"
password = "SuperSecretPassword123!"

# Hardcoded API token (risk of exposure!)
api_token = "123456789abcdef123456789"

# Hardcoded private key (major security vulnerability!)
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCqGKukO1De7Zhrt4Ga3F0skO1De7Zhrt4Ga3F0skO1De7Zhrt4
Ga3F0skO1De7Zhrt4Ga3F0skO1De7Zhrt4Ga3F0skO1De7Zhrt4Ga3F0skO1De7Z
hrt4Ga3F0skO1De7Zhrt4Ga3F0skO1De7Zhrt4Ga3F0skO1De7Zhrt4Ga3F0sIDAQABAoGB
AIhlx5qo9Vqo9VbUMZjFmDZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUM
ZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFj
UMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZj
FjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUMZjFjUM
-----END RSA PRIVATE KEY-----"""

# Hardcoded OAuth token (should be securely stored!)
oauth_token = "ghp_19C69I1Ghg5OyR5J4T75DB9S7ReAVBfGh"

# Dummy function that uses the sensitive information (for illustrative purposes)
def connect_to_service():
    # Pretend we're using the sensitive information here to connect to a service
    print(f"Connecting with email {email} and password {password}")
    print(f"Using API token: {api_token}")
    print(f"Authenticating with OAuth token: {oauth_token}")
    # ... more code

# Main function to run the dummy function
if __name__ == "__main__":
    connect_to_service()
