from aws_cdk import (
    Stack,
    Tags,
    CfnOutput,
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
)
from constructs import Construct
from network_stack import NetworkStack
from domain_stack import DomainStack
from cognito_stack import CognitoStack


class DashboardsProxyStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        # Extract props from kwargs
        network_stack = kwargs.pop("network_stack")
        search_stack = kwargs.pop("search_stack")
        cognito_stack = kwargs.pop("cognito_stack")
        ip_address_range = kwargs.pop("ip_address_range", "10.0.0.0/16")
        
        super().__init__(scope, id, **kwargs)
        
        env_tag = network_stack.environment_tag
        
        # Create security group for proxy
        proxy_security_group = ec2.SecurityGroup(self, "ProxySecurityGroup",
            vpc=network_stack.vpc,
            description="Rules for allowing access to the proxy",
            allow_all_outbound=False,
        )
        
        # Add ingress rule for HTTPS
        proxy_security_group.add_ingress_rule(
            ec2.Peer.ipv4(ip_address_range),
            ec2.Port.tcp(443),
            "Allow HTTPS access over specified IP range"
        )
        
        # Add egress rule for all traffic
        proxy_security_group.add_egress_rule(
            ec2.Peer.ipv4("0.0.0.0/0"),
            ec2.Port.all_traffic(),
            "Allow proxy to download resources from the internet"
        )
        
        # Tag security group
        Tags.of(proxy_security_group).add("Name", f"{env_tag}-dashboards-proxy-sg")
        
        # Create elastic IP for proxy
        proxy_ip = ec2.CfnEIP(self, "ProxyIPAddress",
            domain="vpc",
        )
        
        # Create network interface for proxy
        proxy_network_interface = ec2.CfnNetworkInterface(self, "ProxyNetworkInterface",
            description="Dashboards Proxy ENI",
            private_ip_address=f"{network_stack.vpc_cidr_prefix}.0.150",
            group_set=[proxy_security_group.security_group_id],
            subnet_id=network_stack.public_subnets[0].subnet_id,
        )
        
        # Tag network interface
        Tags.of(proxy_network_interface).add("Name", f"{env_tag}-dashboards-proxy-if")
        
        # Associate elastic IP with network interface
        ec2.CfnEIPAssociation(self, "AssociateEIPProxy",
            allocation_id=proxy_ip.attr_allocation_id,
            network_interface_id=proxy_network_interface.ref,
        )
        
        # Create IAM role for proxy
        proxy_role = iam.Role(self, "ProxyRole",
            role_name=f"{env_tag}-dashboards-proxy-role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            path="/",
        )
        
        # Add managed policy for SSM
        proxy_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
        )
        
        # Add policies to role
        proxy_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:Describe*"],
                resources=["*"],
            )
        )
        
        proxy_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["es:ESHttp*"],
                resources=[
                    f"arn:aws:es:{self.region}:{self.account}:domain/{search_stack.domain.domain_name}/*",
                ],
            )
        )
        
        # Create instance profile for proxy
        proxy_instance_profile = iam.CfnInstanceProfile(self, "ProxyInstanceProfile",
            path="/",
            roles=[proxy_role.role_name],
        )
        
        # Create user data for proxy
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "#!/bin/bash -xe",
            "dnf update -y aws-cfn-bootstrap",
            "dnf update -y aws-cli",
            "dnf update -y amazon-ssm-agent",
            "mkdir /usr/share/es-scripts",
            "sleep 5",
            "dnf install nginx -y",
            "openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/cert.key -out /etc/nginx/cert.crt -subj /C=US/ST=./L=./O=./CN=."
        )
        
        # Create nginx config
        nginx_config = f"""server {{
    listen 443 ssl;
    server_name $host;
    rewrite ^/$ https://$host/_dashboards redirect;

    ssl_certificate           /etc/nginx/cert.crt;
    ssl_certificate_key       /etc/nginx/cert.key;

    client_max_body_size 100M;

    # ssl on;
    ssl_session_cache  builtin:1000  shared:SSL:10m;
    ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
    ssl_prefer_server_ciphers on;

    # local variables for host resolution for the DNS timeouts.  Use variable to resolve intead of URI which grabs once
    # ...it will uses DNS resolver in case cached entry for the IP has expired
    set $es_endpoint {search_stack.domain.domain_endpoint};
    set $cognito_endpoint {cognito_stack.user_pool_domain.domain_name}.auth.{self.region}.amazoncognito.com;

    # resolver settings to avoid cache issues with DNS resolution and Amazon ES
    resolver {network_stack.vpc_cidr_prefix}.0.2 169.254.169.253 ipv6=off valid=30s;

    location ^~ /_dashboards {{
        # Forward requests to Dashboards
        proxy_pass https://$es_endpoint;

        # Handle redirects to Amazon Cognito
        proxy_redirect https://$cognito_endpoint https://$host;

        # Update cookie domain and path
        proxy_cookie_domain $es_endpoint $host;

        proxy_set_header Accept-Encoding "";
        sub_filter_types *;
        sub_filter $es_endpoint $host;
        sub_filter_once off;

        # Response buffer settings
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }}

    location ~ \\/(log|sign|error|fav|forgot|change|oauth2|saml) {{
        # Forward requests to Cognito
        proxy_pass https://$cognito_endpoint;

        # Handle redirects to Dashboards
        proxy_redirect https://$es_endpoint https://$host;

        # Handle redirects to Amazon Cognito
        proxy_redirect https://$cognito_endpoint https://$host;

        # Update cookie domain
        proxy_cookie_domain $cognito_endpoint $host;
    }}
}}"""
        
        # Create EC2 instance for proxy
        dashboards_proxy = ec2.Instance(self, "DashboardsProxy",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.M6I, ec2.InstanceSize.LARGE),
            machine_image=ec2.MachineImage.lookup(
                name="amzn2-ami-hvm-*-x86_64-gp2",
                owners=["amazon"],
            ),
            user_data=user_data,
            role=proxy_role,
        )
        
        # Add user data to create nginx config
        dashboards_proxy.user_data.add_commands(
            f"""cat > /etc/nginx/conf.d/default.conf << 'EOL'
{nginx_config}
EOL""",
            "systemctl enable nginx",
            "systemctl start nginx"
        )
        
        # Tag instance
        Tags.of(dashboards_proxy).add("Name", f"{env_tag}-dashboards-proxy")
        
        # Create asset bucket for Lambda code
        asset_bucket = s3.Bucket(self, "LambdaAssetBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        
        # Create OpenSearch Python layer
        open_search_py_layer = lambda_.LayerVersion(self, "OpenSearchpyLayer",
            code=lambda_.Code.from_asset("/workspace/lambda/opensearch-py-layer"),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            description="OpenSearch Python SDK layer",
        )
        
        # Create IAM role for OpenSearch initialization Lambda
        os_init_lambda_role = iam.Role(self, "OSInitLambdaRole",
            role_name=f"{env_tag}-OS_INIT-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        
        # Add managed policies to role
        os_init_lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
        )
        os_init_lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
        )
        
        # Add policies to role
        os_init_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:Describe*"],
                resources=["*"],
            )
        )
        
        os_init_lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["es:ESHttp*"],
                resources=[
                    f"arn:aws:es:{self.region}:{self.account}:domain/{search_stack.domain.domain_name}/*",
                ],
            )
        )
        
        # Create OpenSearch initialization Lambda function
        os_init_lambda_function = lambda_.Function(self, "OSInitLambdaFunction",
            function_name=f"{env_tag}-OS_INIT",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="os_init_function.lambda_handler",
            code=lambda_.Code.from_asset("/workspace/lambda/os_init_function"),
            role=os_init_lambda_role,
            vpc=network_stack.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnets=[
                    network_stack.private_subnets_app[0],
                    network_stack.private_subnets_app[1],
                ],
            ),
            security_groups=[proxy_security_group],
            memory_size=256,
            timeout=Duration.seconds(180),
            layers=[open_search_py_layer],
            environment={
                "ES_ENDPOINT": f"https://{search_stack.domain.domain_endpoint}",
            },
        )
        
        # Outputs
        CfnOutput(self, "DashboardsProxyRoleArn",
            description="Dashboards proxy role ARN for FGAC role mapping.",
            value=proxy_role.role_arn,
            export_name=f"{self.stack_name}-DashboardsProxyRoleArn",
        )
        
        CfnOutput(self, "DashboardsProxyURL",
            description="Dashboards Proxy Public IP address.",
            value=f"https://{proxy_ip.ref}/_dashboards",
            export_name=f"{self.stack_name}-DashboardsProxyURL",
        )
        
        CfnOutput(self, "OpenSearchInitRoleARN",
            description="ARN for the Lambda intitialisation function.",
            value=os_init_lambda_role.role_arn,
            export_name=f"{self.stack_name}-OSInitRoleARN",
        )