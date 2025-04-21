from aws_cdk import (
    Stack,
    CfnOutput,
    aws_s3 as s3,
    aws_iam as iam,
    aws_lambda as lambda_,
    custom_resources as cr,
    Duration,
    Fn,
    RemovalPolicy,
)
from constructs import Construct
import json


class CopyZipStack(Stack):
    def __init__(self, scope: Construct, id: str, network_stack, **kwargs) -> None:
        # Extract props from kwargs
        source_bucket_name = kwargs.pop("source_bucket_name", "aws-security-blog-content")
        source_key_prefix = kwargs.pop("source_key_prefix", "public/sample/2791-deploy-amazon-opensearch-cluster-ingest-logs-amazon-security-lake/")
        objects_to_copy = kwargs.pop("objects_to_copy", [
            "os_init_function.py.zip",
            "Klayers-p312-opensearch-py-94f72145-b3aa-4698-b962-5ca70864c436.zip"
        ])
        
        super().__init__(scope, id, **kwargs)
        
        # Get environment tag from network stack
        env_tag = network_stack.environment_tag
        
        # Create S3 bucket for Lambda function code
        lambda_zips_bucket = s3.Bucket(
            self,
            "LambdaZipsBucket",
            bucket_name=Fn.join(
                "-",
                [
                    "os-asl-lambda",
                    Fn.ref("AWS::AccountId"),
                    Fn.select(2, Fn.split("/", Fn.ref("AWS::StackId")))
                ]
            ),
            encryption=s3.BucketEncryption.KMS_MANAGED,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
        )
        
        # Add environment tag to bucket
        lambda_zips_bucket.add_tag(
            "Environment",
            Fn.import_value(f"{network_stack.stack_name}-EnvTag")
        )
        
        # Create IAM role for the Lambda function
        copy_zips_role = iam.Role(
            self,
            "CopyZipsRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            path="/"
        )
        
        # Add inline policy to the role
        copy_zips_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{source_bucket_name}/{source_key_prefix}*"]
            )
        )
        
        copy_zips_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:PutObject", "s3:DeleteObject"],
                resources=[f"arn:aws:s3:::{lambda_zips_bucket.bucket_name}/*"]
            )
        )
        
        # Create Lambda function for copying objects
        copy_zips_function = lambda_.Function(
            self,
            "CopyZipsFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json
import logging
import threading
import boto3
import cfnresponse

def copy_objects(source_bucket, dest_bucket, prefix, objects):
    s3 = boto3.client('s3')
    for o in objects:
        key = prefix + o
        copy_source = {
            'Bucket': source_bucket,
            'Key': key
        }
        print(('copy_source: %s' % copy_source))
        print(('dest_bucket = %s'%dest_bucket))
        print(('key = %s' %key))
        response = s3.get_object(Bucket=source_bucket, Key=key)
        print ('downloaded object %s' %key)
        s3.put_object(
          Bucket=dest_bucket,
          Key=o,
          Body=response['Body'].read(),
          ServerSideEncryption='aws:kms',
          BucketKeyEnabled=True
          )
        print ('put object object %s' %key)

def delete_objects(bucket, prefix, objects):
    s3 = boto3.client('s3')
    objects = {'Objects': [{'Key': o} for o in objects]}
    s3.delete_objects(Bucket=bucket, Delete=objects)


def timeout(event, context):
    logging.error('Execution is about to time out, sending failure response to CloudFormation')
    cfnresponse.send(event, context, cfnresponse.FAILED, {}, None)


def handler(event, context):
    # make sure we send a failure to CloudFormation if the function
    # is going to timeout
    timer = threading.Timer((context.get_remaining_time_in_millis()
              / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()

    print(('Received event: %s' % json.dumps(event)))
    status = cfnresponse.SUCCESS
    try:
        source_bucket = event['ResourceProperties']['SourceBucket']
        dest_bucket = event['ResourceProperties']['DestBucket']
        prefix = event['ResourceProperties']['Prefix']
        objects = event['ResourceProperties']['Objects']
        if event['RequestType'] == 'Delete':
            delete_objects(dest_bucket, prefix, objects)
        else:
            copy_objects(source_bucket, dest_bucket, prefix, objects)
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = cfnresponse.FAILED
    finally:
        timer.cancel()
        cfnresponse.send(event, context, status, {}, None)
            """),
            role=copy_zips_role,
            timeout=Duration.seconds(240),
        )
        
        # Create custom resource to invoke the Lambda function
        copy_zips_custom_resource = cr.AwsCustomResource(
            self,
            "CopyZips",
            on_create={
                "service": "Lambda",
                "action": "invoke",
                "parameters": {
                    "FunctionName": copy_zips_function.function_name,
                    "Payload": json.dumps({
                        "RequestType": "Create",
                        "ResourceProperties": {
                            "SourceBucket": source_bucket_name,
                            "DestBucket": lambda_zips_bucket.bucket_name,
                            "Prefix": source_key_prefix,
                            "Objects": objects_to_copy
                        }
                    })
                },
                "physical_resource_id": cr.PhysicalResourceId.of("CopyZipsInvocation")
            },
            on_delete={
                "service": "Lambda",
                "action": "invoke",
                "parameters": {
                    "FunctionName": copy_zips_function.function_name,
                    "Payload": json.dumps({
                        "RequestType": "Delete",
                        "ResourceProperties": {
                            "SourceBucket": source_bucket_name,
                            "DestBucket": lambda_zips_bucket.bucket_name,
                            "Prefix": source_key_prefix,
                            "Objects": objects_to_copy
                        }
                    })
                },
                "physical_resource_id": cr.PhysicalResourceId.of("CopyZipsInvocation")
            },
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["lambda:InvokeFunction"],
                    resources=[copy_zips_function.function_arn]
                )
            ]),
            resource_type="Custom::CopyZips"
        )
        
        # Outputs
        CfnOutput(
            self,
            "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName"
        )
        
        CfnOutput(
            self,
            "LambdaFunctionObjectBucket",
            value=lambda_zips_bucket.bucket_name,
            description="The bucket name for the function zips",
            export_name=f"{self.stack_name}-LambdaFunctionObjectBucket"
        )
        
        # Store bucket as property for other stacks to use
        self.lambda_zips_bucket = lambda_zips_bucket
