#!/usr/bin/env python3
import aws_cdk as cdk
from aws_cdk import NestedStack, Stack
from network_stack import NetworkStack
from cognito_stack import CognitoStack
from domain_stack import DomainStack
from dashboards_proxy_stack import DashboardsProxyStack
from osi_stack import OSIStack
from slr_stack import SLRStack

class MainStack(Stack):
    def __init__(self, scope, id, **kwargs):
        # Get environment name from context or default to 'dev'
        env_name = scope.node.try_get_context("environmentTag") or "dev"
        # Get project name from context or default
        project_name = scope.node.try_get_context("project") or "ocsf"
        # Create a unique stack name
        stack_name = f"{project_name}-{env_name}"
        # Pass the stack_name to the parent class
        super().__init__(scope, id, stack_name=stack_name, **kwargs)

        # Create the network stack
        network_stack = NetworkStack(self, f"{stack_name}-network",
            environment_tag=app.node.try_get_context("environmentTag") or "dev",
            cidr_prefix=app.node.try_get_context("cidrPrefix") or "10.0",
        )

        # Create the SLR stack
        slr_stack = SLRStack(self, f"{stack_name}-slr",
            network_stack=network_stack,
        )

# # Create the Cognito stack
# cognito_stack = CognitoStack(app, "CognitoStack",
#     network_stack=network_stack,
# )

# # Create the OpenSearch domain stack
# domain_stack = DomainStack(app, "DomainStack",
#     network_stack=network_stack,
#     cognito_stack=cognito_stack,
#     search_domain_name=app.node.try_get_context("searchDomainName") or "opensearch-domain",
#     engine_version=app.node.try_get_context("engineVersion") or "OpenSearch_2.17",
#     data_node_instance_type=app.node.try_get_context("dataNodeInstanceType") or "r6g.large.search",
#     master_node_instance_type=app.node.try_get_context("masterNodeInstanceType") or "r6g.large.search",
#     ebs_volume_size=app.node.try_get_context("ebsVolumeSize") or 10,
# )

# # Create the dashboards proxy stack
# dashboards_proxy_stack = DashboardsProxyStack(app, "DashboardsProxyStack",
#     network_stack=network_stack,
#     search_stack=domain_stack,
#     cognito_stack=cognito_stack,
#     ip_address_range=app.node.try_get_context("ipAddressRange") or "10.0.0.0/16",
# )

# # Create the OSI stack
# OSIStack(app, "OSIStack",
#     network_stack=network_stack,
#     search_stack=domain_stack,
#     sec_lake_subscriber_sqs_queue_arn=app.node.try_get_context("secLakeSubscriberSqsQueueArn") or "",
#     sec_lake_subscriber_sqs_queue_url=app.node.try_get_context("secLakeSubscriberSqsQueueURL") or "",
#     security_lake_bucket_name=app.node.try_get_context("securityLakeBucketName") or "",
# )

app = cdk.App()
MainStack(app, "MainStack")
app.synth()

