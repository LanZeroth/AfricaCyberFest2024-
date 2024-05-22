
#!/bin/bash

# Define the directory containing the ZIP files and the password
ZIP_DIR="/path/to/zip/files"
PASSWORD="yourpassword"

# Create a directory to store the extracted files
EXTRACT_DIR="$ZIP_DIR/extracted"
mkdir -p "$EXTRACT_DIR"

# Loop through each ZIP file in the directory
for zipfile in "$ZIP_DIR"/*.zip; do
    echo "Processing $zipfile..."
    
    # Extract the ZIP file using the password
    unzip -P "$PASSWORD" "$zipfile" -d "$EXTRACT_DIR" 2>/dev/null

    # Check if the extraction was successful
    if [ $? -eq 0 ]; then
        echo "Successfully extracted $zipfile"
    else
        echo "Failed to extract $zipfile"
    fi
done