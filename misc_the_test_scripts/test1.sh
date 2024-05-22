
https://afr1cacyb3rfe5t.ctfd.io/challenges
ASTF{1ts_ju57_a5_5impl3_4s_1t_100k5!!!} 


 #!/bin/bash

# Define the directory containing the ZIP files and the password file
ZIP_DIR="/path/to/zip/files"
PASSWORD_FILE="passwords.txt"

# Create a directory to store the extracted files
EXTRACT_DIR="$ZIP_DIR/extracted"
mkdir -p "$EXTRACT_DIR"

# Read the passwords into an array
readarray -t passwords < "$PASSWORD_FILE"

# Counter for passwords array
counter=0

# Loop through each ZIP file in the directory
for zipfile in "$ZIP_DIR"/*.zip; do
    echo "Processing $zipfile..."

    # Get the corresponding password from the array
    PASSWORD="${passwords[$counter]}"

    # Extract the ZIP file using the password
    unzip -P "$PASSWORD" "$zipfile" -d "$EXTRACT_DIR" 2>/dev/null

    # Check if the extraction was successful
    if [ $? -eq 0 ] ; then
        echo "Successfully extracted $zipfile"
    else
        echo "Failed to extract $zipfile"
    fi

    # Increment the counter
    ((counter++))
done