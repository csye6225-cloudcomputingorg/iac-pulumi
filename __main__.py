"""An AWS Python Pulumi program"""

# import pulumi
# from pulumi_aws import s3

# # Create an AWS resource (S3 Bucket)
# bucket = s3.Bucket('my-bucket')

# # Export the name of the bucket
# pulumi.export('bucket_name', bucket.id)

import boto3
import os
import json
import pulumi
import pulumi_aws as aws

from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION")
)

def create_vpc(ec2):
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc.wait_until_available()
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "My_VPC"}])
    return vpc

def create_subnet(ec2, vpc, cidr_block, availability_zone, subnet_type):
    subnet = ec2.create_subnet(CidrBlock=cidr_block, VpcId=vpc.id, AvailabilityZone=availability_zone)
    subnet.create_tags(Tags=[{"Key": "Name", "Value": f"{subnet_type} {availability_zone}"}])
    return subnet

def create_internet_gateway(ec2, vpc):
    ig = ec2.create_internet_gateway()
    vpc.attach_internet_gateway(InternetGatewayId=ig.id)
    return ig

def create_route_table(ec2, vpc, subnet_type):
    route_table = ec2.create_route_table(VpcId=vpc.id)
    route_table.create_tags(Tags=[{"Key": "Name", "Value": f"{subnet_type} Route Table"}])
    return route_table

def create_route_to_igw(route_table, internet_gateway):
    route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway.id)

def main():
    
    # Read the AWS profile from the environment variable AWS_PROFILE
    # aws_profile = os.environ.get("AWS_PROFILE", "default")

    # Create the AWS provider using the AWS_PROFILE environment variable
    # aws_provider = aws.Provider("my-aws-provider", profile=aws_profile)
    
    ec2 = session.resource('ec2')

    vpc = create_vpc(ec2)

    availability_zones = ['us-east-1a', 'us-east-1b', 'us-east-1c']
    public_subnets = []
    private_subnets = []
    
    for index, az in enumerate(availability_zones):
        # Public subnet for current AZ
        public_subnet = create_subnet(ec2, vpc, f'10.0.{index * 2}.0/24', az, "Public")
        public_subnets.append(public_subnet)

        # Private subnet for current AZ
        private_subnet = create_subnet(ec2, vpc, f'10.0.{index * 2 + 1}.0/24', az, "Private")
        private_subnets.append(private_subnet)

    internet_gateway = create_internet_gateway(ec2, vpc)

    public_route_table = create_route_table(ec2, vpc, "Public")
    for subnet in public_subnets:
        public_route_table.associate_with_subnet(SubnetId=subnet.id)

    create_route_to_igw(public_route_table, internet_gateway)

    private_route_table = create_route_table(ec2, vpc, "Private")
    for subnet in private_subnets:
        private_route_table.associate_with_subnet(SubnetId=subnet.id)
        
    # Create an Application Security Group
    application_security_group = aws.ec2.SecurityGroup(
        "application-security-group",
        description="Security Group for EC2 instances hosting web applications",
        vpc_id=vpc.id,  # Using the VPC created earlier
    )

    # Ingress rules to allow specific ports from anywhere
    ingress_rules = [
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow SSH",
            from_port=22,
            to_port=22,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTP",
            from_port=80,
            to_port=80,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTPS",
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow Application",
            from_port=5000,
            to_port=5000,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"]
        )
    ]

    # Apply the ingress rules to the security group
    for rule in ingress_rules:
        aws.ec2.SecurityGroupRule(
            f"ingress-rule-{rule.from_port}-{rule.to_port}",
            security_group_id=application_security_group.id,
            from_port=rule.from_port,
            to_port=rule.to_port,
            protocol=rule.protocol,
            cidr_blocks=rule.cidr_blocks,
            description=rule.description,
            type="ingress",
        )
        
    with open('manifest.json', 'r') as json_file:
        manifest_data = json.load(json_file)
        ami_details = manifest_data['builds'][0]['artifact_id']

    print(ami_details.split(':')[1])
    ec2_instance = aws.ec2.Instance (
        "my-ec2-instance",
        instance_type = "t2.micro",
        vpc_security_group_ids = [application_security_group.id],
        subnet_id = public_subnets[0].id,
        associate_public_ip_address = True,
        ami = ami_details.split(':')[1],  # Use the AMI ID from Packer
        tags = {
            "Name": "MyEC2Instance",
        },
    )
    
    # pulumi.export('public_ip', ec2_instance.public_ip) //figure out later

if __name__ == '__main__':
    main()