from aws_cdk import (
    Stack,
    Fn,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    aws_osis as osis,
)
from constructs import Construct
from network_stack import NetworkStack
from domain_stack import DomainStack


class OSIStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        # Extract props from kwargs
        network_stack = kwargs.pop("network_stack")
        search_stack = kwargs.pop("search_stack")
        sec_lake_subscriber_sqs_queue_arn = kwargs.pop("sec_lake_subscriber_sqs_queue_arn", "")
        sec_lake_subscriber_sqs_queue_url = kwargs.pop("sec_lake_subscriber_sqs_queue_url", "")
        security_lake_bucket_name = kwargs.pop("security_lake_bucket_name", "")
        
        super().__init__(scope, id, **kwargs)
        
        # Create log group for OpenSearch Ingestion
        open_search_ingestion_log_group = logs.LogGroup(self, "OpenSearchIngestionLogGroup",
            log_group_name=f"/aws/vendedlogs/OpenSearchIngestion/{self.stack_name}-pipeline",
            retention=logs.RetentionDays.ONE_YEAR,
        )
        
        # Create security group for OpenSearch Ingestion Pipeline
        osi_pipeline_security_group = ec2.SecurityGroup(self, "OpensearchIngestionPipelineSecurityGroup",
            vpc=network_stack.vpc,
            description="Allow outbound from OSI Pipeline to Domain",
            allow_all_outbound=False,
        )
        
        # Add egress rule for HTTPS to VPC CIDR
        osi_pipeline_security_group.add_egress_rule(
            ec2.Peer.ipv4(network_stack.vpc_cidr_block),
            ec2.Port.tcp(443),
            "Allow outbound from OSI Pipeline to Domain"
        )
        
        # Create IAM role for OpenSearch Ingestion Pipeline
        osi_pipeline_role = iam.Role(self, "OpensearchIngestionPipelineRole",
            role_name=f"OpenSearchIngestionPipelineRole-{Fn.select(0, Fn.split('-', Fn.select(2, Fn.split('/', self.stack_id))))}",
            assumed_by=iam.ServicePrincipal("osis-pipelines.amazonaws.com"),
        )
        
        # Add policies to the role
        osi_pipeline_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadFromS3",
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{security_lake_bucket_name}/*"],
            )
        )
        
        osi_pipeline_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReceiveAndDeleteSqsMessages",
                effect=iam.Effect.ALLOW,
                actions=[
                    "sqs:DeleteMessage",
                    "sqs:ReceiveMessage",
                    "sqs:changemessagevisibility",
                ],
                resources=[sec_lake_subscriber_sqs_queue_arn],
            )
        )
        
        osi_pipeline_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["es:DescribeDomain"],
                resources=[f"arn:aws:es:*:{self.account}:domain/*"],
            )
        )
        
        osi_pipeline_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["es:ESHttp*"],
                resources=[f"{search_stack.domain.domain_arn}/*"],
            )
        )
        
        osi_pipeline_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/vendedlogs/OpenSearchIngestion/{self.stack_name}-pipeline:*",
                ],
            )
        )
        
        # Create OpenSearch Ingestion Pipeline using L1 construct (since L2 construct is not available yet)
        osi_pipeline = osis.CfnPipeline(self, "OpensearchIngestionPipeline",
            pipeline_configuration_body=f"""version: "2"
s3-log-pipeline:
  source:
    s3:
      # Prevent data loss by only considering logs to be processed successfully after they are received by the opensearch sink
      acknowledgments: true
      notification_type: "sqs"
      compression: "none"
      notification_source: "eventbridge"
      codec:
        parquet:
      sqs:
        queue_url: "{sec_lake_subscriber_sqs_queue_url}"
        visibility_timeout: "60s"
        visibility_duplication_protection: true
      aws:
        # Provide the region to use for aws credentials
        region: "{self.region}"
        # Provide the role to assume for requests to SQS and S3
        sts_role_arn: "{osi_pipeline_role.role_arn}"
  processor:
    - drop_events:
        drop_when: '/status_code != "OK" and /metadata/product/name == "Amazon VPC"'
    - lowercase_string:
        with_keys: [ "/metadata/product/name", "/class_name" ]
    - substitute_string:
        entries:
          - source: "/metadata/product/name"
            from: "\\s"
            to: "_"
          - source: "/class_name"
            from: "\\s"
            to: "_"
    - delete_entries:
        with_keys: [ "s3" ]
  sink:
    - opensearch:
        hosts: [ "{search_stack.domain.domain_endpoint}" ] 
        aws:
          sts_role_arn: "{osi_pipeline_role.role_arn}"
          region: "{self.region}"
          serverless: false
        index: "ocsf-${{!/metadata/version}}-${{!/class_uid}}-${{!/class_name}}" """,
            buffer_options={
                "persistent_buffer_enabled": False,
            },
            min_units=2,
            pipeline_name=f"osi-{Fn.select(0, Fn.split('-', Fn.select(2, Fn.split('/', self.stack_id))))}",
            max_units=4,
            log_publishing_options={
                "is_logging_enabled": True,
                "cloud_watch_log_destination": {
                    "log_group": open_search_ingestion_log_group.log_group_name,
                },
            },
            vpc_options={
                "subnet_ids": [subnet.subnet_id for subnet in network_stack.private_subnets_app],
                "security_group_ids": [osi_pipeline_security_group.security_group_id],
            },
        )
        
        # Add dependency to ensure role is created before pipeline
        osi_pipeline.node.add_dependency(osi_pipeline_role)
        
        # Output IAM role ARN
        CfnOutput(self, "IAMRoleArn",
            description="ARN of the created OpensearchIngestionPipelineRole role",
            value=osi_pipeline_role.role_arn,
        )