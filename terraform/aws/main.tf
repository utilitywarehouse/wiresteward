data "aws_ami" "flatcar_stable" {
  most_recent      = true
  executable_users = ["all"]
  owners           = ["075585003325"] // this is the account id that Flatcar use to release AMI images

  filter {
    name   = "name"
    values = ["Flatcar-stable-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  name_regex = "^Flatcar-stable-\\d{4}.\\d+.\\d+-hvm$"
}

resource "aws_security_group" "wiresteward" {
  name        = local.name
  description = "Allows wireguard and SSH traffic from anywhere, oauth2-proxy traffic from ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = local.name
  }
}

resource "aws_eip" "peer" {
  count  = local.instance_count
  domain = "vpc"

  tags = {
    Name = local.name
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_eip_association" "peer" {
  count         = local.instance_count
  instance_id   = aws_instance.peer[count.index].id
  allocation_id = aws_eip.peer[count.index].id
}

resource "aws_instance" "peer" {
  count                       = local.instance_count
  ami                         = var.ami_id != "" ? var.ami_id : data.aws_ami.flatcar_stable.id
  instance_type               = var.instance_type
  vpc_security_group_ids      = concat([aws_security_group.wiresteward.id], var.additional_security_group_ids)
  subnet_id                   = var.subnet_ids[count.index]
  source_dest_check           = false
  user_data                   = data.template_file.userdata[count.index].rendered
  user_data_replace_on_change = true
  iam_instance_profile        = aws_iam_instance_profile.peer.name

  lifecycle {
    ignore_changes = [ami]
  }

  root_block_device {
    volume_type = "gp2"
    volume_size = "10"
  }

  credit_specification {
    cpu_credits = "unlimited"
  }

  tags = {
    Name  = local.name
    owner = "system"
  }
}

resource "aws_route53_record" "peer" {
  count   = local.instance_count
  zone_id = var.dns_zone_id
  name    = var.wireguard_endpoints[count.index]
  type    = "A"
  ttl     = "60"
  records = [aws_eip.peer[count.index].public_ip]
}
