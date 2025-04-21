# OpenSearch Security Lake Integration CDK Project (Python)

This project contains CDK code that transforms the nested CloudFormation stack for OpenSearch Security Lake integration into a CDK application that can be deployed without referencing external buckets.

## Project Structure

- `app.py` - Main CDK application entry point
- `network_stack.py` - Network infrastructure (VPC, subnets, etc.)
- `slr_stack.py` - Service Linked Role creation for OpenSearch and OSI services
- `cognito_stack.py` - Cognito resources for authentication
- `domain_stack.py` - OpenSearch domain configuration
- `dashboards_proxy_stack.py` - Proxy for OpenSearch Dashboards
- `osi_stack.py` - OpenSearch Ingestion pipeline for Security Lake integration

## Prerequisites

- AWS CDK installed
- Python 3.9 or higher
- AWS CLI configured with appropriate credentials

## Deployment Instructions

1. Create and activate a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   pip install -e .
   ```

3. Configure deployment parameters in `cdk.json` or pass them as context variables:
   ```
   cdk deploy -c environmentTag=prod -c cidrPrefix=10.0 ...
   ```

4. Deploy the stacks:
   ```
   cdk deploy --all
   ```

## Required Parameters

- `environmentTag` - Tag for the environment (e.g., dev, test, prod)
- `cidrPrefix` - CIDR prefix for the VPC (e.g., 10.0, 192.168)
- `searchDomainName` - Name for the OpenSearch domain
- `secLakeSubscriberSqsQueueArn` - ARN of the SQS queue from your Security Lake subscriber
- `secLakeSubscriberSqsQueueURL` - URL of the SQS queue from your Security Lake subscriber
- `securityLakeBucketName` - Name of the Security Lake S3 bucket

## Lambda Functions

The project includes Lambda functions for:
- OpenSearch initialization
- Cognito user creation
- Service Linked Role creation for OpenSearch and OpenSearch Ingestion services

These functions are bundled with the CDK application and don't require external S3 buckets.

## Security Considerations

- The OpenSearch domain is deployed in a VPC with appropriate security groups
- Cognito is used for authentication
- IAM roles follow the principle of least privilege
- All data is encrypted at rest and in transit


