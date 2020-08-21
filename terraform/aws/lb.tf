resource "aws_security_group" "wiresteward-lb" {
  name        = "${local.name}-lb"
  description = "Allows HTTPS traffic from anywhere"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-lb"
  }
}

resource "aws_lb" "wiresteward" {
  name               = local.name
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.wiresteward-lb.id]

  tags = {
    Name = local.name
  }
}

resource "aws_acm_certificate" "cert" {
  domain_name       = "${var.role_name}.${var.dns_zone_name}"
  validation_method = "DNS"
}

resource "aws_route53_record" "cert_validation" {
  name    = aws_acm_certificate.cert.domain_validation_options.0.resource_record_name
  type    = aws_acm_certificate.cert.domain_validation_options.0.resource_record_type
  zone_id = var.dns_zone_id
  records = [aws_acm_certificate.cert.domain_validation_options.0.resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [aws_route53_record.cert_validation.fqdn]
}

resource "aws_lb_listener" "wiresteward_443" {
  load_balancer_arn = aws_lb.wiresteward.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.cert.certificate_arn

  default_action {
    target_group_arn = aws_lb_target_group.wiresteward_4180.arn
    type             = "forward"
  }
}

resource "aws_lb_target_group" "wiresteward_4180" {
  vpc_id   = var.vpc_id
  port     = 4180
  protocol = "HTTP"

  health_check {
    matcher = "302"
  }

  # https://github.com/terraform-providers/terraform-provider-aws/issues/636#issuecomment-397459646
  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = local.name
  }
}

resource "aws_lb_target_group_attachment" "peer" {
  count            = local.instance_count
  target_group_arn = aws_lb_target_group.wiresteward_4180.arn
  target_id        = aws_instance.peer[count.index].id
}

resource "aws_route53_record" "wiresteward" {
  zone_id = var.dns_zone_id
  name    = "${var.role_name}.${var.dns_zone_name}"
  type    = "CNAME"
  ttl     = "600"
  records = [aws_lb.wiresteward.dns_name]
}
