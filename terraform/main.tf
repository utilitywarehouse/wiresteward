variable "name" {
  default = "wg-testing"
}

variable "subnet" {
  default = "10.200.200.0/24"
}

provider "aws" {
  profile = "uw-dev-admin"
  region  = "eu-west-1"
}

data "http" "address" {
  url = "https://ipv4.wtfismyip.com/text"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "debian" {
  owners      = ["379101102735"] # https://wiki.debian.org/Cloud/AmazonEC2Image/Stretch
  most_recent = true

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_key_pair" "peer" {
  key_name   = "dkaragiannis"
  public_key = file("~/.ssh/id_rsa.pub")
}

resource "aws_security_group" "peer" {
  name        = var.name
  description = "Allows WireGuard and SSH traffic"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.address.body)}/32"]
  }

  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["${chomp(data.http.address.body)}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "peer" {
  count         = 1
  ami           = data.aws_ami.debian.id
  instance_type = "t2.micro"
  key_name      = aws_key_pair.peer.key_name
  // security_groups = [aws_security_group.peer.id]
  security_groups        = [aws_security_group.peer.name]
  vpc_security_group_ids = [aws_security_group.peer.id]

  user_data = <<EOF
#cloud-config
write_files:
  - path: /etc/apt/sources.list.d/unstable.list
    content: deb http://deb.debian.org/debian/ unstable main
  - path: /etc/apt/preferences.d/limit-unstable
    content: |
      Package: *
      Pin: release a=unstable
      Pin-Priority: 90
  - path: /etc/wireguard/wg0.conf
    permissions: '0400'
    content: |
      [Interface]
      Address = ${cidrhost(var.subnet, count.index + 1)}/${element(split("/", var.subnet), 1)}
      PrivateKey = ${chomp(file("${path.module}/remote/s${count.index}"))}
      ListenPort = 51820
runcmd:
  - apt update
  - apt upgrade --yes
  - apt install wireguard --yes
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0
EOF

  tags = {
    Name = var.name
  }
}

output "public_ips" {
  value = aws_instance.peer[0].public_ip
}
