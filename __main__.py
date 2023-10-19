import boto3
import os
import pulumi_aws as aws
import pulumi
from dotenv import load_dotenv
from pulumi_aws import get_availability_zones

load_dotenv()

aws_profile = "demo" 

config = pulumi.Config("aws")
region = config.require("region")

session = boto3.Session(profile_name=aws_profile, region_name=region)

def create_vpc(ec2):
    vpc = ec2.create_vpc(CidrBlock=os.getenv("vpc_cidr_block"))
    vpc.wait_until_available()
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "WebAppVPC"}])
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
    route_table.create_route(DestinationCidrBlock=os.getenv("ig_cidr_block"), GatewayId=internet_gateway.id)


def create_or_get_key_pair(ec2_client):
    try:
        # Try fetching an existing key pair
        print('inside try')
        response = ec2_client.describe_key_pairs(KeyNames=["my-keypair_demo"])
        if response and response.get("KeyPairs"):
            print('inside if')
            return response["KeyPairs"][0]["KeyName"]
    except:
        pass

    # If key pair doesn't exist, then create one using Boto3
    new_key_pair = ec2_client.create_key_pair(KeyName="my-keypair_demo")
    print("key pair doesn't exist")
    key_material = new_key_pair["KeyMaterial"]
    print('key material')
    
    key_file_path = os.path.abspath("my-keypair_demo.pem")
    print('keyfile path')
    with open(key_file_path, "w") as key_file:
        print('open file')
        key_file.write(key_material)
    print(f"Key saved to: {key_file_path}")

    # Ensure permissions of the .pem file are set correctly
    os.chmod("my-keypair_demo.pem", 0o400)

    # Use the public key from the new key pair with Pulumi's aws.ec2.KeyPair
    pulumi_key_pair = aws.ec2.KeyPair("my-keypair_demo", public_key=new_key_pair["KeyMaterial"])
    return pulumi_key_pair.key_name


def fetch_ami_id(ec2_client):
    owner_id = "547346458147"
    filters = [{"Name": "owner-id", "Values": [owner_id]}]

    response = ec2_client.describe_images(Filters=filters)

    # Check if private AMIs were found.
    if response.get("Images"):
        ami_id = response["Images"][0]["ImageId"]
        pulumi.export("private_ami_id", ami_id)
        return ami_id
    else:
        raise Exception("Private AMI not found")


def main():
    
    ec2 = session.resource('ec2')
    ec2_client = session.client('ec2')

    vpc = create_vpc(ec2)

    availability_zones = get_availability_zones().names
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
            cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTP",
            from_port=80,
            to_port=80,
            protocol="tcp",
            cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTPS",
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow Application",
            from_port=3001,
            to_port=3001,
            protocol="tcp",
            cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow Application",
            from_port=5000,
            to_port=5000,
            protocol="tcp",
            cidr_blocks=[os.getenv("ig_cidr_block")]
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

    print(fetch_ami_id(ec2_client))
    
    key_name = create_or_get_key_pair(ec2_client)
    
    ec2_instance = aws.ec2.Instance (
        "webapp-ec2-instance",
        instance_type = "t2.micro",
        vpc_security_group_ids = [application_security_group.id],
        subnet_id = public_subnets[0].id,
        associate_public_ip_address = True,
        ami = fetch_ami_id(ec2_client),  # Use the AMI ID from Packer
        key_name=key_name,
        tags = {
            "Name": "WebApp_EC2Instance",
        },
    )


if __name__ == '__main__':
    main()
