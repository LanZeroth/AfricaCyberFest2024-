#!/bin/bash

# Path to the desktop and the ZIP file
ZIP_FILE="$HOME/Desktop/misc.zip"

# Wordlist file (RockYou.txt)
WORDLIST="/usr/share/wordlists/rockyou.txt"

# Flag format to search for
FLAG_FORMAT="ACTF{"

# Temporary directory to extract files
EXTRACT_DIR="/tmp/extracted_zip"

# Create the extraction directory
mkdir -p "$EXTRACT_DIR"

# Check if the ZIP file exists
if [ ! -f "$ZIP_FILE" ]; then
    echo "Error: ZIP file $ZIP_FILE not found."
    exit 1
fi

# Loop through each password in the RockYou.txt wordlist
while IFS= read -r password; do
    echo "Trying password: $password"

    # Attempt to unzip the file with the current password
    output=$(unzip -P "$password" -l "$ZIP_FILE" 2>&1)

    # Check if the flag is found in the output
    if echo "$output" | grep -q "$FLAG_FORMAT"; then
        echo "Password found: $password"

        # Extract the file contents to a temporary directory
        unzip -P "$password" "$ZIP_FILE" -d "$EXTRACT_DIR"

        # Check if the flag file exists and display its content
        flag_file="$EXTRACT_DIR/flag.txt"
        if [ -f "$flag_file" ]; then
            echo "Flag content:"
            cat "$flag_file"
        else
            echo "Flag file not found in $ZIP_FILE"
        fi

        # Clean up the temporary directory
        rm -rf "$EXTRACT_DIR"

        # Exit the loop once the flag is found
        break
    fi
done < "$WORDLIST"