"""An AWS Python Pulumi program"""

# import pulumi
# from pulumi_aws import s3

# # Create an AWS resource (S3 Bucket)
# bucket = s3.Bucket('my-bucket')

# # Export the name of the bucket
# pulumi.export('bucket_name', bucket.id)

import boto3
import os
from dotenv import load_dotenv

load_dotenv()

# AWS_ACCESS_KEY_ID = "AKIAX64DEEYRXRJWOQ44"
# AWS_SECRET_ACCESS_KEY = "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"
# AWS_REGION = "us-east-1"

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

if __name__ == '__main__':
    main()