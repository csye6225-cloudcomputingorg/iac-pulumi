packer {
  required_plugins {
    amazon = {
      version = ">=0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ssh_username" {
  type    = string
  default = "admin"
}

variable "subnet_id" {
  type    = string
  default = "subnet-025f87a6da259c0bd"
}

variable "ami_region" {
  type    = list(string)
  default = ["us-east-1"]
}

source "amazon-ebs" "debian" {
  region      = "${var.aws_region}"
  ami_name    = "csye6225_test_ami-${formatdate("YYYY-MM-DD-hhmmss", timestamp())}"
  ami_regions = "${var.ami_region}"
  ami_users   = ["404824748503"]

  aws_polling {
    delay_seconds = 50
    max_attempts  = 50
  }

  instance_type = "t2.micro"

  source_ami_filter {
    filters = {
      name                = "debian-12-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "x86_64"
    }
    owners      = ["136693071363"]
    most_recent = true
  }

  ssh_username = "${var.ssh_username}"
  subnet_id    = "${var.subnet_id}"
  profile      = "dev"

  launch_block_device_mappings {
    delete_on_termination = true
    device_name           = "/dev/xvda"
    volume_size           = 8
    volume_type           = "gp2"
  }
}


build {
  sources = [
    "source.amazon-ebs.debian"
  ]

  provisioner "file" {
    source      = "app/webapp-main.zip"
    destination = "/home/admin/webapp.zip"
  }

  provisioner "shell" {
    script = "installation_script.sh"
  }

  # Capture the AMI ID as a user variable
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}