# Store provided userdata in s3 bucket and provide a new one that fetches it

resource "aws_s3_bucket" "userdata" {
  bucket = "${var.bucket_prefix}-ignition-userdata-wiresteward"

}

resource "aws_s3_bucket_server_side_encryption_configuration" "userdata" {
  bucket = aws_s3_bucket.userdata.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "userdata" {
  bucket = aws_s3_bucket.userdata.id

  block_public_acls   = true
  block_public_policy = true
}

resource "aws_s3_object" "userdata" {
  count   = local.instance_count
  bucket  = aws_s3_bucket.userdata.id
  key     = "wiresteward-config-${count.index}-${sha1(var.ignition[count.index])}.json"
  content = var.ignition[count.index]
}

data "template_file" "userdata" {
  count = local.instance_count
  template = jsonencode(
    {
      ignition = {
        version = "2.2.0",
        config = {
          replace = {
            source = "s3://${aws_s3_bucket.userdata.id}/wiresteward-config-${count.index}-${sha1(var.ignition[count.index])}.json",
            aws = {
              region = "eu-west-1"
            }
          }
        }
      }
    }
  )
}

# Instance profile to allow fetching the userdata

data "aws_iam_policy_document" "peer_auth" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "peer" {
  name                 = "${local.iam_prefix}wiresteward-peer"
  assume_role_policy   = data.aws_iam_policy_document.peer_auth.json
  permissions_boundary = var.permissions_boundary
}

data "aws_iam_policy_document" "peer" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.userdata.id}/wiresteward-*"]
  }
}

resource "aws_iam_role_policy" "peer" {
  name   = "${local.iam_prefix}wiresteward-peer"
  role   = aws_iam_role.peer.id
  policy = data.aws_iam_policy_document.peer.json
}

resource "aws_iam_instance_profile" "peer" {
  name = "${local.iam_prefix}wiresteward-peer"
  role = aws_iam_role.peer.name
}
