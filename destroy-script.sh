#!/bin/bash

# Initialize variables
BUCKET_NAME=""

# Function to display usage
usage() {
    echo "Usage: $0 -b <bucket-name>"
    echo "Options:"
    echo "  -b    Specify the bucket name (required)"
    echo "  -h    Display this help message"
    exit 1
}

# Parse command line options
while getopts "b:h" opt; do
    case ${opt} in
        b )
            BUCKET_NAME=$OPTARG
            ;;
        h )
            usage
            ;;
        \? )
            usage
            ;;
    esac
done

# Check if bucket name is provided
if [ -z "$BUCKET_NAME" ]; then
    echo "Error: Bucket name is required"
    usage
fi

# Check if bucket exists
if ! aws s3 ls "s3://$BUCKET_NAME" >/dev/null 2>&1; then
    echo "Error: Bucket '$BUCKET_NAME' does not exist or you don't have access to it"
    exit 1
fi

# Safety prompt
echo "WARNING: This will delete ALL files in bucket '$BUCKET_NAME' and then delete the bucket itself."
read -p "Are you sure you want to continue? (y/N): " confirm

if [[ $confirm != [yY] && $confirm != [yY][eE][sS] ]]; then
    echo "Operation cancelled"
    exit 0
fi

echo "Starting cleanup of bucket: $BUCKET_NAME"

# Delete all objects in the bucket recursively
echo "Removing all files from bucket..."
if aws s3 rm "s3://$BUCKET_NAME" --recursive; then
    echo "Successfully removed all files from bucket"
else
    echo "Error: Failed to remove files from bucket"
    exit 1
fi

# Delete the empty bucket
echo "Deleting bucket..."
if aws s3 rb "s3://$BUCKET_NAME"; then
    echo "Successfully deleted bucket: $BUCKET_NAME"
else
    echo "Error: Failed to delete bucket"
    exit 1
fi

echo "Cleanup complete!"
