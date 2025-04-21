# This stack contains two functions to prepare for the deployment. One  initialises the service linked roles for OpenSearch. The other uploads the function code and assets to an S3 bucket. It then deploys one Lambda function which will initialise OpenSearch.

from aws_cdk import (
    NestedStack,
    CfnOutput,
    aws_iam as iam,
    aws_lambda as lambda_,
    custom_resources as cr,
    Duration
)
from constructs import Construct
import json
import boto3


class SLRStack(NestedStack):
    def __init__(self, scope: Construct, id: str, network_stack, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        # Get environment tag from network stack
        env_tag = network_stack.environment_tag
        def generate_slr_roles():
            print('creating boto client')
            iam_client = boto3.client('iam')
            try:
                print('creating service linked role for es.amazon.com')
                bury_to_skip_exists = iam_client.create_service_linked_role(
                    AWSServiceName='es.amazonaws.com'
                )
                print('api call to create_service_linked_role completed')
                print(bury_to_skip_exists)
            except Exception as e:
                print('Exception: {0}'.format(e))
                print('burying exception as role probably exists already and will skip')
            try:
                print('creating service linked role for osis.amazon.com')
                bury_to_skip_exists = iam_client.create_service_linked_role(
                    AWSServiceName='osis.amazonaws.com'
                )
                print('api call to create_service_linked_role completed')
                print(bury_to_skip_exists)
            except Exception as e:
                print('Exception: {0}'.format(e))
                print('burying exception as role probably exists already and will skip')

        generate_slr_roles()


        
        # Outputs
        CfnOutput(
            self, 
            "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName"
        )

