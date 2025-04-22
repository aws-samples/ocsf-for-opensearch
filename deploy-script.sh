#!/bin/sh

# Function to create service linked role
create_service_linked_role() {
    local service_name=$1
    echo "Creating service linked role for $service_name"
    
    if aws iam create-service-linked-role --aws-service-name "$service_name" 2>/dev/null; then
        echo "Successfully created service linked role for $service_name"
        return 0
    else
        # Check if error was due to role already existing
        if aws iam get-role --role-name "AWSServiceRoleFor${service_name//./-}" >/dev/null 2>&1; then
            echo "Service linked role for $service_name already exists, skipping creation"
            return 0
        else
            echo "Warning: Could not create service linked role for $service_name, but continuing..."
            return 0 
        fi
    fi
}

# Main execution
echo "Starting service linked role creation process..."

# Create service linked role for OpenSearch
if create_service_linked_role "es.amazonaws.com"; then
    echo "OpenSearch service linked role setup completed"
else
    echo "burying exception as role probably exists already and will skip"
    exit 1
fi

# Create service linked role for OpenSearch Ingestion
if create_service_linked_role "osis.amazonaws.com"; then
    echo "OpenSearch Ingestion service linked role setup completed"
else
    echo "burying exception as role probably exists already and will skip"
    exit 1
fi

echo "Service linked role creation process completed successfully"

files_to_check=(
    "deployment/cfn/quickstart-cognito.json"
    "deployment/cfn/quickstart-dashboards-proxy.json"
    "deployment/cfn/quickstart-domain.json"
    "deployment/cfn/quickstart-kickoff.json"
    "deployment/cfn/quickstart-network.json"
    "deployment/cfn/quickstart-slr.json"
    "deployment/Assets/Klayers-p312-opensearch-py-94f72145-b3aa-4698-b962-5ca70864c436.zip"
    "deployment/Assets/os_init_function.py"
    "schemas/component_templates/ocsf_1_1_0_actor_body.json"
    "schemas/index_templates/ocsf_1_1_0_1001_file_system_activity_body.json"
)

for file in "${files_to_check[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' is missing!"
        exit 1  # Exit with an error code if a file is not found
    fi
done

echo "All ${#files_to_check[@]} required assets are present"

## Zip relevant files
zip deployment/Assets/os_init_function.py.zip deployment/Assets/os_init_function.py
zip -r schemas/component_templates.zip schemas/component_templates
zip -r schemas/index_templates.zip schemas/index_templates
echo "Assets zipped"

# # Create bucket for deployment assets
echo "Creating S3 bucket for deployment assets"
uuid=$(mktemp -u XXXXXXXXXX | tr 'A-Z' 'a-z')
assets_bucket_name=os-stack-deploy-assets-$uuid
aws s3 mb s3://$assets_bucket_name

# Upload workshop assets
echo "Uploading cloudformation templates  to $assets_bucket_name S3 bucket..."
aws s3 cp deployment/cfn s3://$assets_bucket_name/cloudformation \
  --recursive \

echo "Uploading schemas to $assets_bucket_name S3 bucket..."
aws s3 cp schemas s3://$assets_bucket_name/schemas \
  --recursive \
  --exclude "*" \
  --include "component_templates.zip" \
  --include "index_templates.zip" \

echo "Uploading Lambda functions to $assets_bucket_name S3 bucket..."
aws s3 cp deployment/Assets s3://$assets_bucket_name/lambda \
  --recursive \
  --exclude "*" \
  --include "Klayers-p312-opensearch-py-94f72145-b3aa-4698-b962-5ca70864c436.zip" \
  --include "os_init_function.py.zip" \

echo "Setup complete. Asset bucket name: $assets_bucket_name"
