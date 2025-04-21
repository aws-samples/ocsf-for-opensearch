from aws_cdk import (
    NestedStack,
    Tags,
    CfnOutput,
    aws_ec2 as ec2,
)
from constructs import Construct
from typing import List


class NetworkStack(NestedStack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        # Extract props from kwargs
        environment_tag = kwargs.pop("environment_tag", "dev")
        cidr_prefix = kwargs.pop("cidr_prefix", "10.0")
        
        super().__init__(scope, id, **kwargs)
        
        self.environment_tag = environment_tag
        self.vpc_cidr_prefix = cidr_prefix
        self.vpc_cidr_block = f"{cidr_prefix}.0.0/21"
        
        # Create VPC
        self.vpc = ec2.Vpc(
            self, 
            "VPC",
            ip_addresses=ec2.IpAddresses.cidr(self.vpc_cidr_block),
            max_azs=3,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    cidr_mask=24,
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                ),
                ec2.SubnetConfiguration(
                    cidr_mask=24,
                    name="PrivateApp",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                ),
            ],
            nat_gateways=1,
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )
        
        # Tag VPC
        Tags.of(self.vpc).add("Name", f"{environment_tag}-vpc")
        
        # Get subnets
        self.private_subnets_app = self.vpc.private_subnets
        self.public_subnets = self.vpc.public_subnets
        
        # Tag subnets
        for i, subnet in enumerate(self.public_subnets):
            Tags.of(subnet).add("Name", f"{environment_tag}-sn-pub{i}")
        
        for i, subnet in enumerate(self.private_subnets_app):
            Tags.of(subnet).add("Name", f"{environment_tag}-sn-priv-app{i}")
        
        # Outputs
        CfnOutput(self, "StackName",
            value=self.stack_name,
            export_name=f"{self.stack_name}-StackName",
        )
        
        CfnOutput(self, "VPCCIDRBlock",
            value=self.vpc_cidr_block,
            export_name=f"{self.stack_name}-VPCCIDRBlock",
        )
        
        CfnOutput(self, "VPCCIDRPrefix",
            value=self.vpc_cidr_prefix,
            export_name=f"{self.stack_name}-VPCCIDRPrefix",
        )
        
        CfnOutput(self, "EnvTag",
            value=self.environment_tag,
            export_name=f"{self.stack_name}-EnvTag",
        )
        
        CfnOutput(self, "VPCID",
            value=self.vpc.vpc_id,
            export_name=f"{self.stack_name}-VPCID",
        )
        
        # Output subnets
        for i, subnet in enumerate(self.public_subnets):
            CfnOutput(self, f"PublicSubnet{i}",
                value=subnet.subnet_id,
                export_name=f"{self.stack_name}-PublicSubnet{i}",
            )
        
        for i, subnet in enumerate(self.private_subnets_app):
            CfnOutput(self, f"PrivateSubnetApp{i}",
                value=subnet.subnet_id,
                export_name=f"{self.stack_name}-PrivateSubnetApp{i}",
            )
        
        # Output CIDR ranges
        CfnOutput(self, "ApplicationCIDRRange",
            value=f"{cidr_prefix}.4.0/22",
            export_name=f"{self.stack_name}-ApplicationCIDRRange",
        )
        
        CfnOutput(self, "PublicCIDRRange",
            value=f"{cidr_prefix}.0.0/22",
            export_name=f"{self.stack_name}-PublicCIDRRange",
        )
        
        # Output route tables
        CfnOutput(self, "PublicRoutingTable",
            value=self.vpc.public_subnets[0].route_table.route_table_id,
            export_name=f"{self.stack_name}-PublicRoutingTable",
        )
        
        CfnOutput(self, "PrivateRoutingTable",
            value=self.vpc.private_subnets[0].route_table.route_table_id,
            export_name=f"{self.stack_name}-PrivateRoutingTable",
        )
        
        # Output NAT public IP
        nat_gateway_eip = self.vpc.public_subnets[0].node.find_child("EIP")
        CfnOutput(self, "NATPublicIP",
            value=nat_gateway_eip.ref,
            export_name=f"{self.stack_name}-NATPublicIP",
        )