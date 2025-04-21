from aws_cdk import (
    Stack,
    CfnOutput,
    Fn,
    Duration,
    aws_cognito as cognito,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_secretsmanager as secretsmanager,
    custom_resources as cr,
)
from constructs import Construct
from network_stack import NetworkStack
import json


class CognitoStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        # Extract props from kwargs
        network_stack = kwargs.pop("network_stack")
        
        super().__init__(scope, id, **kwargs)
        
        env_tag = network_stack.environment_tag
        
        # Create Cognito password secret
        cognito_password = secretsmanager.Secret(self, "CognitoPassword",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username": "administrator"}',
                generate_string_key="password",
                password_length=16,
                exclude_characters='"@/\\',
            ),
            description="Password for OpenSearch Cognito Proxy",
        )
        
        # Create Lambda execution role
        lambda_execution_role = iam.Role(self, "LambdaExecutionRole",
            role_name=f"{env_tag}_lambda_role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            path="/",
        )
        
        # Add policies to Lambda execution role
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=["arn:aws:lambda:*:*:function:*"],
            )
        )
        
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["arn:aws:logs:*:*:*:*"],
            )
        )
        
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["cognito-idp:*"],
                resources=["arn:aws:cognito-idp:*:*:userpool/*"],
            )
        )
        
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["es:*"],
                resources=["*"],
            )
        )
        
        lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["secretsmanager:GetSecretValue"],
                resources=[cognito_password.secret_arn],
            )
        )
        
        # Create Cognito user pool
        self.user_pool = cognito.UserPool(self, "CognitoUserPool",
            user_pool_name=f"user_pool_{env_tag}",
            self_sign_up_enabled=False,
            auto_verify=cognito.AutoVerify(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
        )
        
        # Create Cognito identity pool
        self.identity_pool = cognito.CfnIdentityPool(self, "CognitoIdentityPool",
            identity_pool_name=f"identity_pool_{env_tag}",
            allow_unauthenticated_identities=False,
        )
        
        # Create auth role for Cognito users
        self.auth_role = iam.Role(self, "AuthUserRole",
            role_name=f"cog_auth_role_{env_tag}",
            assumed_by=iam.FederatedPrincipal(
                "cognito-identity.amazonaws.com",
                {
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": self.identity_pool.ref,
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated",
                    },
                },
                "sts:AssumeRoleWithWebIdentity"
            ),
        )
        
        # Add policies to auth role
        self.auth_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "mobileanalytics:PutEvents",
                    "cognito-sync:*",
                    "cognito-identity:*",
                ],
                resources=["*"],
            )
        )
        
        # Attach role to identity pool
        cognito.CfnIdentityPoolRoleAttachment(self, "IdentityPoolRoleAttachment",
            identity_pool_id=self.identity_pool.ref,
            roles={
                "authenticated": self.auth_role.role_arn,
            },
        )
        
        # Create Cognito domain
        domain_prefix = Fn.select(0, Fn.split("-", Fn.select(2, Fn.split("/", self.stack_id))))
        self.user_pool_domain = cognito.UserPoolDomain(self, "CognitoDomain",
            user_pool=self.user_pool,
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"{domain_prefix}-{env_tag}",
            ),
        )
        
        # Create wiring function to create initial Cognito user
        wiring_function = lambda_.Function(self, "WiringFunction",
            runtime=lambda_.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
from __future__ import print_function

import boto3
import json
import os
import cfnresponse

def get_secret():
    region_name = os.environ['AWS_REGION']
    secret_name = os.environ['SECRET_NAME']

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            raise ValueError("Secret not found in SecretString")

def create_cognito_user():
    cognito_idp = boto3.client('cognito-idp')
    secret = get_secret()
    try:
        response = cognito_idp.admin_create_user(
            UserPoolId=os.environ['USER_POOL_ID'],
            Username='administrator',
            TemporaryPassword=secret['password']
        )
    except Exception as e:
        print('Exception creating Cognito user: {0}'.format(e))

def handler(event, context):
    if event['RequestType'] == 'Create':
        try:
            create_cognito_user()
        except Exception as e:
            send_response(event, context, cfnresponse.FAILED)
    send_response(event, context, cfnresponse.SUCCESS)

def send_response(event, context, status_code):
    response_data = {}
    response_data['Data'] = 'done'
    cfnresponse.send(event, context, status_code, response_data, "CustomResourcePhysicalID")
            """),
            role=lambda_execution_role,
            timeout=Duration.seconds(300),
            environment={
                "SECRET_NAME": cognito_password.secret_name,
                "REGION": self.region,
                "STACK_PREFIX": env_tag,
                "USER_POOL_ID": self.user_pool.user_pool_id,
            },
        )
        
        # Create custom resource to invoke the wiring function
        cr.AwsCustomResource(self, "WiringFunctionInvocation",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": wiring_function.function_name,
                    "Payload": json.dumps({
                        "RequestType": "Create",
                        "ServiceToken": wiring_function.function_arn,
                        "ResponseURL": "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/response",
                        "StackId": self.stack_id,
                        "RequestId": "CustomResourceRequest",
                        "LogicalResourceId": "WiringFunctionInvocation",
                        "ResourceType": "Custom::WiringFunctionInvocation",
                        "ResourceProperties": {
                            "ServiceToken": wiring_function.function_arn,
                            "Region": self.region,
                        },
                    }),
                },
                physical_resource_id=cr.PhysicalResourceId.of("WiringFunctionInvocation"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[wiring_function.function_arn],
                ),
            ]),
        )
        
        # Outputs
        CfnOutput(self, "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName",
        )
        
        CfnOutput(self, "CognitoUser",
            value="administrator",
            export_name=f"{self.stack_name}-CognitoUser",
        )
        
        CfnOutput(self, "CognitoUserPoolEndpoint",
            value=f"{self.user_pool_domain.domain_name}.auth.{self.region}.amazoncognito.com",
            export_name=f"{self.stack_name}-CognitoUserPoolEndpoint",
        )
        
        CfnOutput(self, "CognitoUserPool",
            value=self.user_pool.user_pool_id,
            export_name=f"{self.stack_name}-CognitoUserPool",
        )
        
        CfnOutput(self, "CognitoIdentityPool",
            value=self.identity_pool.ref,
            export_name=f"{self.stack_name}-CognitoIdentityPool",
        )
        
        CfnOutput(self, "AuthRoleARN",
            value=self.auth_role.role_arn,
            export_name=f"{self.stack_name}-AuthRoleARN",
        )
