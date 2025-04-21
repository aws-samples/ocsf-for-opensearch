## This stack creates two lambda functions. One Lambda function initialises the service linked roles for OpenSearch, the other uploads the function code and assets to an S3 bucket for future lambda functions

from aws_cdk import (
    NestedStack,
    CfnOutput,
    aws_iam as iam,
    aws_lambda as lambda_,
    custom_resources as cr,
    Duration
)
from constructs import Construct


class SLRStack(NestedStack):
    def __init__(self, scope: Construct, id: str, network_stack, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        
        # Get environment tag from network stack
        env_tag = network_stack.environment_tag
        
        # Create Lambda execution role for SLR creation
        lambda_slr_execution_role = iam.Role(
            self, 
            "LambdaSLRExecutionRole",
            role_name=f"{env_tag}_lambda_slr_role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            path="/",
        )
        
        # Add inline policy to the role with specific name
        slr_policy_document = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["lambda:InvokeFunction"],
                    resources=["arn:aws:lambda:*:*:function:*"]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources=["arn:aws:logs:*:*:*:*"]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["iam:CreateServiceLinkedRole"],
                    resources=["*"]
                )
            ]
        )
        
        lambda_slr_execution_role.attach_inline_policy(
            iam.Policy(
                self,
                "LambdaSLRPolicy",
                policy_name=f"{env_tag}_lambda_slr_policy",
                document=slr_policy_document
            )
        )
        
        # Create Lambda function for SLR creation
        slr_function = lambda_.Function(
            self,
            "ServiceLinkedRoleFunction",
            runtime=lambda_.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
            from __future__ import print_function

            import json

            import boto3
            import cfnresponse

            def handler(event, context):
                if event['RequestType'] == 'Create':
                    try:
                        create_service_linked_role()
                    except Exception as e:
                        send_response(event, context, cfnresponse.FAILED)
                send_response(event, context, cfnresponse.SUCCESS)

            def create_service_linked_role():
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

            def send_response(event, context, status_code):
                response_data = {}
                response_data['Data'] = 'done'
                cfnresponse.send(event, context, status_code, response_data, "CustomResourcePhysicalID")
            """),
            role=lambda_slr_execution_role,
            timeout=Duration.seconds(300),
        )
        
        # Create custom resource to invoke the Lambda function
        cr.AwsCustomResource(
            self,
            "ServiceLinkedRoleFunctionInvocation",
            on_create={
                "service": "Lambda",
                "action": "invoke",
                "parameters": {
                    "FunctionName": slr_function.function_name,
                    "Payload": '{"RequestType": "Create"}'
                },
                "physical_resource_id": cr.PhysicalResourceId.of("ServiceLinkedRoleInvocation")
            },
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
            ),
            resource_type="Custom::SLRFunctionInvocation"
        )
        






        # Outputs
        CfnOutput(
            self, 
            "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName"
        )

