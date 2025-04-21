from aws_cdk import (
    Stack,
    Tags,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_opensearchservice as opensearch,
)
from constructs import Construct
from network_stack import NetworkStack
from cognito_stack import CognitoStack


class DomainStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        # Extract props from kwargs
        network_stack = kwargs.pop("network_stack")
        cognito_stack = kwargs.pop("cognito_stack")
        search_domain_name = kwargs.pop("search_domain_name", "opensearch-domain")
        engine_version = kwargs.pop("engine_version", "OpenSearch_2.17")
        data_node_instance_type = kwargs.pop("data_node_instance_type", "r6g.large.search")
        master_node_instance_type = kwargs.pop("master_node_instance_type", "r6g.large.search")
        ebs_volume_size = kwargs.pop("ebs_volume_size", 10)
        
        super().__init__(scope, id, **kwargs)
        
        env_tag = network_stack.environment_tag
        
        # Create security group for OpenSearch
        self.security_group = ec2.SecurityGroup(self, "SearchSecurityGroup",
            vpc=network_stack.vpc,
            description="Rules for allowing access to the cluster resources",
            allow_all_outbound=False,
        )
        
        # Add ingress rule for HTTPS
        self.security_group.add_ingress_rule(
            ec2.Peer.ipv4(network_stack.vpc_cidr_block),
            ec2.Port.tcp(443),
            "Allow network access from proxy"
        )
        
        # Add egress rule for all traffic within VPC
        self.security_group.add_egress_rule(
            ec2.Peer.ipv4(network_stack.vpc_cidr_block),
            ec2.Port.all_traffic(),
            "Allow traffic between the nodes and with the proxy"
        )
        
        # Tag security group
        Tags.of(self.security_group).add("Name", f"{env_tag}_search_sg")
        
        # Create role for OpenSearch Cognito integration
        role_for_cognito = iam.Role(self, "RoleForAmazonOpenSearchServiceCognito",
            role_name=f"es_cognito_role_{env_tag}",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("es.aws.internal"),
                iam.ServicePrincipal("es.amazonaws.com")
            ),
            path="/",
        )
        
        # Add policy to role
        role_for_cognito.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cognito-idp:DescribeUserPool",
                    "cognito-idp:CreateUserPoolClient",
                    "cognito-idp:DeleteUserPoolClient",
                    "cognito-idp:DescribeUserPoolClient",
                    "cognito-idp:AdminInitiateAuth",
                    "cognito-idp:AdminUserGlobalSignOut",
                    "cognito-idp:ListUserPoolClients",
                    "cognito-identity:DescribeIdentityPool",
                    "cognito-identity:UpdateIdentityPool",
                    "cognito-identity:SetIdentityPoolRoles",
                    "cognito-identity:GetIdentityPoolRoles",
                ],
                resources=["*"],
            )
        )
        
        role_for_cognito.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=["*"],
                conditions={
                    "StringLike": {
                        "iam:PassedToService": "cognito-identity.amazonaws.com",
                    },
                },
            )
        )
        
        # Create OpenSearch domain
        self.domain = opensearch.Domain(self, "OpenSearchDomain",
            domain_name=search_domain_name,
            version=opensearch.EngineVersion.from_string(engine_version),
            capacity={
                "data_node_instance_type": data_node_instance_type,
                "data_nodes": 3,
                "master_node_instance_type": master_node_instance_type,
                "master_nodes": 3,
            },
            ebs={
                "volume_size": ebs_volume_size,
                "volume_type": ec2.EbsDeviceVolumeType.GP3,
            },
            zone_awareness={
                "enabled": True,
                "availability_zone_count": 3,
            },
            logging={
                "slow_search_log_enabled": True,
                "app_log_enabled": True,
                "slow_index_log_enabled": True,
            },
            cognito_dashboards_auth={
                "identity_pool_id": cognito_stack.identity_pool.ref,
                "user_pool_id": cognito_stack.user_pool.user_pool_id,
                "role": role_for_cognito,
            },
            node_to_node_encryption=True,
            encryption_at_rest={
                "enabled": True,
            },
            enforce_https=True,
            tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2,
            access_policies=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[iam.ArnPrincipal(cognito_stack.auth_role.role_arn)],
                    actions=["es:*"],
                    resources=[
                        f"arn:aws:es:{self.region}:{self.account}:domain/{search_domain_name}/*",
                    ],
                ),
            ],
            vpc=network_stack.vpc,
            vpc_subnets=[
                {
                    "subnets": network_stack.private_subnets_app,
                },
            ],
            security_groups=[self.security_group],
            advanced_options={
                "indices.query.bool.max_clause_count": "4096",
            },
        )
        
        # Tag domain
        Tags.of(self.domain).add("Name", f"{env_tag}_search_domain")
        
        # Outputs
        CfnOutput(self, "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName",
        )
        
        CfnOutput(self, "SearchEndpoint",
            value=self.domain.domain_endpoint,
            export_name=f"{self.stack_name}-SearchEndpoint",
        )
        
        CfnOutput(self, "SearchDomainName",
            value=search_domain_name,
            export_name=f"{self.stack_name}-SearchDomainName",
        )
        
        CfnOutput(self, "SearchDomainARN",
            value=self.domain.domain_arn,
            export_name=f"{self.stack_name}-SearchDomainARN",
        )