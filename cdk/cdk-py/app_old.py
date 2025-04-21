#!/usr/bin/env python3
import aws_cdk as cdk
from network_stack import NetworkStack
from cognito_stack import CognitoStack
from domain_stack import DomainStack
from dashboards_proxy_stack import DashboardsProxyStack
from osi_stack import OSIStack

app = cdk.App()

# Create the network stack
network_stack = NetworkStack(app, "NetworkStack",
    environment_tag=app.node.try_get_context("environmentTag") or "dev",
    cidr_prefix=app.node.try_get_context("cidrPrefix") or "10.0",
)

# Create the Cognito stack
cognito_stack = CognitoStack(app, "CognitoStack",
    network_stack=network_stack,
)

# Create the OpenSearch domain stack
domain_stack = DomainStack(app, "DomainStack",
    network_stack=network_stack,
    cognito_stack=cognito_stack,
    search_domain_name=app.node.try_get_context("searchDomainName") or "opensearch-domain",
    engine_version=app.node.try_get_context("engineVersion") or "OpenSearch_2.17",
    data_node_instance_type=app.node.try_get_context("dataNodeInstanceType") or "r6g.large.search",
    master_node_instance_type=app.node.try_get_context("masterNodeInstanceType") or "r6g.large.search",
    ebs_volume_size=app.node.try_get_context("ebsVolumeSize") or 10,
)

# Create the dashboards proxy stack
dashboards_proxy_stack = DashboardsProxyStack(app, "DashboardsProxyStack",
    network_stack=network_stack,
    search_stack=domain_stack,
    cognito_stack=cognito_stack,
    ip_address_range=app.node.try_get_context("ipAddressRange") or "10.0.0.0/16",
)

# Create the OSI stack
OSIStack(app, "OSIStack",
    network_stack=network_stack,
    search_stack=domain_stack,
    sec_lake_subscriber_sqs_queue_arn=app.node.try_get_context("secLakeSubscriberSqsQueueArn") or "",
    sec_lake_subscriber_sqs_queue_url=app.node.try_get_context("secLakeSubscriberSqsQueueURL") or "",
    security_lake_bucket_name=app.node.try_get_context("securityLakeBucketName") or "",
)

app.synth()