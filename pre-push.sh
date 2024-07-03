#!/bin/bash

# Define the size limit in bytes (50 MB in this case)
SIZE_LIMIT=$((50 * 1024 * 1024))

# Function to track large files with Git LFS
track_large_files() {
    local large_files=$(git ls-tree -r -l HEAD | awk -v limit=$SIZE_LIMIT '$4 > limit { print $5 }')
    if [ -n "$large_files" ]; then
        echo "Tracking large files with Git LFS:"
        for file in $large_files; do
            echo "Tracking $file"
            git lfs track "$file"
        done
        git add .gitattributes
        git commit -m "Track large files with Git LFS"
    fi
}

# Ensure we're tracking large files before pushing
track_large_files

# Proceed with the push
exec git push "$@"
