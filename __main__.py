import boto3
import os
import pulumi_aws as aws
import pulumi
import base64
from pulumi_aws import rds
from dotenv import load_dotenv
from pulumi_aws import get_availability_zones
from pulumi_aws import autoscaling, ec2, lb

load_dotenv()

# aws_profile = "dev" 

config = pulumi.Config("aws")
region = config.require("region")

session = boto3.Session(profile_name=config.get("profile"), region_name=region)

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

def create_rds_parameter_group():
    parameter_group = rds.ParameterGroup("webapp-db-parameter-group",
        family="mysql8.0",
        description="Custom DB Parameter Group",
        parameters=[{
            "name": "character_set_server",
            "value": "utf8mb4",
        },
        {
            "name": "collation_server",
            "value": "utf8mb4_unicode_ci",
        },
        {
            "name": "max_connections",
            "value": "100", 
            "apply_method": "pending-reboot"
         }])

    return parameter_group

def create_rds_instance(db_security_group, db_parameter_group, private_subnets):
    rds_instance = rds.Instance("webapp-db",
        allocated_storage=20,
        storage_type=os.getenv("storage_type"),
        engine=os.getenv("db_engine"),
        engine_version=os.getenv("db_version"),
        instance_class=os.getenv("db_instance_class"),  
        db_name=os.getenv("db_name"),
        parameter_group_name=db_parameter_group.name,
        password=os.getenv("db_password"),
        username=os.getenv("db_username"),
        publicly_accessible=False,
        skip_final_snapshot=True,
        vpc_security_group_ids=[db_security_group.id],
        db_subnet_group_name=rds.SubnetGroup("webapp-db-subnet-group",
            subnet_ids=[subnet.id for subnet in private_subnets]
        ).name,
    )

    return rds_instance


def fetch_ami_id(ec2_client):
    owner_id = os.getenv("owner_id")
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
    
    #Load balancer Security Group
    load_balancer_sg = aws.ec2.SecurityGroup('load_balancer_sg',
    description='Enable access to the load balancer',
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTP",
            from_port=80,
            to_port=80,
            protocol='tcp',
            cidr_blocks=[os.getenv("ig_cidr_block")],
        ), 
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow HTTPS",
            from_port=443,
            to_port=443,
            protocol='tcp',
            cidr_blocks=[os.getenv("ig_cidr_block")],
        )
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", # Allow all outbound protocols
            from_port=0, 
            to_port=0,
            cidr_blocks=[os.getenv("ig_cidr_block")],
        ),
    ],
)
        
    # Create an Application Security Group
    application_security_group = aws.ec2.SecurityGroup(
        "application-security-group",
        description="Security Group for EC2 instances hosting web applications",
        vpc_id=vpc.id,
        ingress = [
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow SSH",
            from_port=22,
            to_port=22,
            protocol="tcp",
            security_groups=[load_balancer_sg.id]
            # cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow Application",
            from_port=3001,
            to_port=3001,
            protocol="tcp",
            security_groups=[load_balancer_sg.id]
            # cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
    ],
        egress = [
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow outbound traffic from the application",
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=[os.getenv("ig_cidr_block")]
        ),
    ]
    )     

    # Create a Load Balancer
    load_balancer = lb.LoadBalancer('app-load-balancer',
    security_groups=[load_balancer_sg.id],
    subnets=[public_subnets[0].id, public_subnets[1].id, public_subnets[2].id],
    load_balancer_type="application",
    internal=False,
    enable_deletion_protection=False
    )
    
    # Create a target group that listens on port 3001
    target_group = lb.TargetGroup('target-group',
        port=3001,
        protocol='HTTP',
        target_type='instance',
        vpc_id=vpc.id,
        health_check={
            "enabled": True,
            "port":"3001", 
            "path": '/healthz',
            "protocol": "HTTP",
            "timeout": 3,
            "healthy_threshold": 3,
            "unhealthy_threshold": 3,
            "interval": 30,
        },
    )
    
    # Then create a listener for the load balancer
    listener = lb.Listener('http_listener',
        load_balancer_arn=load_balancer.arn,
        protocol="HTTP",
        port=80,
        default_actions=[{
            'type': 'forward',
            'target_group_arn': target_group.arn,
        }]
    )
    
    print(fetch_ami_id(ec2_client))
    
    key_name = create_or_get_key_pair(ec2_client)
    
    # Creating Database Security Group
    db_security_group = aws.ec2.SecurityGroup(
        "db-security-group",
        description="Security Group for RDS instances",
        vpc_id=vpc.id,
    )
    
    db_ingress_rules = [
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow MySQL traffic from application",
            from_port=3306,
            to_port=3306,
            protocol="tcp",
        ),
    ]

    db_egress_rules = [
        aws.ec2.SecurityGroupIngressArgs(
            description="Allow outbound traffic from the application",
            from_port=0,
            to_port=0,
            protocol="-1",
        ),
    ]

    # Adding ingress rule for MySQL
    for db_rule in db_ingress_rules:
        aws.ec2.SecurityGroupRule(
            f"db-ingress-rule-{db_rule.from_port}-{db_rule.to_port}",
            security_group_id=db_security_group.id,
            source_security_group_id=application_security_group.id,
            from_port=db_rule.from_port,
            to_port=db_rule.to_port,
            protocol=db_rule.protocol,
            description=db_rule.description,
            type="ingress",
        )

    # Adding ingress rule for MySQL
    for db_rule in db_egress_rules:
        aws.ec2.SecurityGroupRule(
            f"db-egress-rule-{db_rule.from_port}-{db_rule.to_port}",
            security_group_id=db_security_group.id,
            source_security_group_id=application_security_group.id,
            from_port=db_rule.from_port,
            to_port=db_rule.to_port,
            protocol=db_rule.protocol,
            description=db_rule.description,
            type="egress",
        )
        
        
    db_parameter_group = create_rds_parameter_group()
    rds_instance = create_rds_instance(db_security_group, db_parameter_group, private_subnets)
    
    print(rds_instance)
    
    # define IAM role
    role = aws.iam.Role('CloudWatchAgentRole',
        assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
            }
        ]
        }"""
    )

    # define IAM policy
    policy = aws.iam.Policy('CloudWatchPolicy',
        description='My policy',
        policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutMetricData",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeTags",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "iam:CreateInstanceProfile",
                    "iam:AddRoleToInstanceProfile"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter"
                ],
                "Resource": "arn:aws:ssm:::parameter/AmazonCloudWatch-*"
            }
        ]
    }"""
    )

    # attach policy to role
    role_policy_attachment = aws.iam.RolePolicyAttachment('RolePolicyAttachment',
        role=role.name,
        policy_arn=policy.arn
    )
    
    
    instance_profile = aws.iam.InstanceProfile("instanceProfile", role=role.name)
    pulumi.export("instance_profile name", instance_profile.name)   

    startup_script = """
                                    
            sudo chown csye6225:csye6225 -R /home/admin/webapp

            sudo systemctl enable amazon-cloudwatch-agent.service
            sudo systemctl start amazon-cloudwatch-agent.service
            
            sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
            -a fetch-config \
            -m ec2 \
            -c file:/home/admin/webapp/cloudwatch-config.json \
            -s
            
            sudo systemctl restart amazon-cloudwatch-agent.service
            
            sudo systemctl daemon-reload
            sudo systemctl enable webapp
            sudo systemctl start webapp
            sudo systemctl restart webapp
        """

    # Form the user data script
    user_data_script = pulumi.Output.all(rds_instance.endpoint, rds_instance.username, rds_instance.password, startup_script).apply(
                        lambda args: f"""#!/bin/bash
                        export DB_HOST={args[0]}
                        export DB_NAME={args[1]}
                        export DB_USER={args[1]}
                        export DB_PASSWORD={args[2]}

                        {args[3]}
                        """
                        )

    # Encode the user data
    user_data_base64 = pulumi.Output.from_input(user_data_script).apply(lambda v: base64.b64encode(v.encode('utf-8')).decode('utf-8'))


    # Create a launch configuration
    launch_template = aws.ec2.LaunchTemplate('webapp-launch-template',
        image_id=fetch_ami_id(ec2_client),
        instance_type=os.getenv("ec2_instance_type"),
        key_name=key_name,
        # vpc_security_group_ids=[application_security_group.id],
        network_interfaces=[{
            "associatePublicIpAddress": True,
            "subnetId": public_subnets[0].id,
            "securityGroups": [application_security_group.id]
        }],
        iam_instance_profile={"name": instance_profile.name},
        user_data=user_data_base64,
    )

    # Create an auto scaling group that refers to your launch configuration
    auto_scaling_group = aws.autoscaling.Group('web-asg',
        vpc_zone_identifiers=[public_subnets[0].id, public_subnets[1].id, public_subnets[2].id],
        min_size=1, 
        max_size=3, 
        desired_capacity=1,
        health_check_type='EC2',
        health_check_grace_period=600,
        force_delete=True,
        termination_policies=['OldestInstance'],
        target_group_arns=[target_group.arn],
        launch_template=aws.autoscaling.GroupLaunchTemplateArgs(
            id=launch_template.id,
            version="$Latest",
        ),
        tags=[{"key": "Name", "value": "webapp-asg", "propagate_at_launch": True}]
    )

    # Create the scale up policy
    scale_up_policy = aws.autoscaling.Policy("scaleup",
        scaling_adjustment=1,
        adjustment_type="ChangeInCapacity",
        cooldown=300,
        autoscaling_group_name=auto_scaling_group.name,
    )

    # Attach a CloudWatch metric that triggers the scale up policy
    cpu_high_alarm = aws.cloudwatch.MetricAlarm("cpuHigh",
        metric_name="CPUUtilization",
        namespace="AWS/EC2",
        comparison_operator="GreaterThanOrEqualToThreshold",
        evaluation_periods=2,
        period=60,
        statistic="Average",
        threshold="5",
        alarm_actions=[scale_up_policy.arn],
        dimensions={
            "AutoScalingGroupName": auto_scaling_group.name,
        },
    )

    # Create the scale down policy
    scale_down_policy = aws.autoscaling.Policy("scaledown",
        scaling_adjustment=-1,
        adjustment_type="ChangeInCapacity",
        cooldown=300,
        autoscaling_group_name=auto_scaling_group.name,
    )

    # Attach a CloudWatch metric that triggers the scale down policy
    cpu_low_alarm = aws.cloudwatch.MetricAlarm("cpuLow",
        metric_name="CPUUtilization",
        namespace="AWS/EC2",
        comparison_operator="LessThanOrEqualToThreshold",
        evaluation_periods=2,
        period=60,
        statistic="Average",
        threshold="3",
        alarm_actions=[scale_down_policy.arn],
        dimensions={
            "AutoScalingGroupName": auto_scaling_group.name,
        },
    )


    # Lookup the Route53 zone
    zone_id = aws.route53.get_zone(name="demo.adityasrprakash.me").zone_id

    dns_record = aws.route53.Record("webserver",
    type="A",
    zone_id=zone_id,
    name="demo.adityasrprakash.me",
    aliases=[
        {
            "name": load_balancer.dns_name,
            "zone_id": load_balancer.zone_id,
            "evaluate_target_health": True,
        },
    ]
    )
    
    
    # Export the RDS endpoint
    pulumi.export("db_endpoint", rds_instance.endpoint)

    # Export the EC2 instance's public IP
    # pulumi.export("ec2_public_ip", ec2_instance.public_ip)    
    
    # Export the log group and log stream names
    # pulumi.export("log_group_name", log_group.name)
    # pulumi.export("log_stream_name", log_stream.name)

    
if __name__ == '__main__':
    main()
