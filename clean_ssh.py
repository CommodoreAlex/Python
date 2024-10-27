#!/usr/bin/env python3

# This will clean SSH keys of newlines and trailing whitespaces
def strip_ssh_key(file_path):
    try:
        with open(file_path, 'r') as file:
            # Read the file contents
            ssh_key = file.read()
            # Strip newlines and trailing whitespace
            stripped_key = ssh_key.replace('\n', '').strip()
        
        # Output the cleaned key
        print("Stripped SSH Key:")
        print(stripped_key)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Replace 'your_ssh_key_file.pub' with the path to your SSH key file
    strip_ssh_key('your_ssh_key_file.pub')
