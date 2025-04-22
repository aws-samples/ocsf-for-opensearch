#!/bin/sh

files_to_check=(
    "automated-scanner.zip"
    "manual-scanner.zip"
    "rate-limit-trigger.zip"
    "sample-static-website.html"
    "scanning-dashboard.html"
    "waf-workshop.yaml"
)

for file in "${files_to_check[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' is missing!"
        exit 1  # Exit with an error code if a file is not found
    fi
done

echo "All ${#files_to_check[@]} required workshop assets are present"

# Create bucket for workshop assets
echo "Creating S3 bucket for workshop assets uploads"
uuid=$(mktemp -u XXXXXXXXXX | tr 'A-Z' 'a-z')
assets_bucket_name=waf-workshop-assets-$uuid
aws s3 mb s3://$assets_bucket_name

# Upload workshop assets
echo "Uploading workshop assets to $assets_bucket_name S3 bucket..."
aws s3 cp . s3://$assets_bucket_name \
  --recursive \
  --exclude "*" \
  --include "automated-scanner.zip" \
  --include "manual-scanner.zip" \
  --include "rate-limit-trigger.zip" \
  --include "sample-static-website.html" \
  --include "scanning-dashboard.html"

echo "Deploying WAF workshop in your account..."
aws cloudformation deploy \
  --capabilities CAPABILITY_IAM \
  --stack-name waf-workshop \
  --template waf-workshop.yaml \
  --parameter-overrides AssetsBucketName=$assets_bucket_name AssetsBucketPrefix=""
