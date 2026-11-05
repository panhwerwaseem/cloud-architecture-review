# Order service for an online shop. Eval fixture: the weaknesses are planted.
# Every password-like value in this folder is a made-up placeholder.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name   = "shop"
  cidr   = "10.20.0.0/16"
}

resource "aws_db_instance" "orders" {
  identifier              = "shop-orders"
  engine                  = "postgres"
  instance_class          = "db.m6g.large"
  allocated_storage       = 100
  username                = "shop"
  password                = "example-only-not-a-real-password"
  publicly_accessible     = true
  backup_retention_period = 0
  skip_final_snapshot     = true
  vpc_security_group_ids  = [aws_security_group.db.id]
}

resource "aws_db_instance" "reporting" {
  identifier              = "shop-reporting"
  engine                  = "postgres"
  instance_class          = var.reporting_instance_class
  allocated_storage       = 200
  username                = "report"
  password                = var.reporting_password
  multi_az                = var.reporting_multi_az
  storage_encrypted       = true
  deletion_protection     = true
  backup_retention_period = var.backup_days
}

resource "aws_dynamodb_table" "carts" {
  name         = "shop-carts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "cart_id"

  attribute {
    name = "cart_id"
    type = "S"
  }
}

resource "aws_s3_bucket" "receipts" {
  bucket = "shop-receipts-example"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "web" {
  ami                    = var.ami
  instance_type          = "t3.large"
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.web.id]
}

resource "aws_ebs_volume" "exports" {
  availability_zone = "eu-west-1a"
  size              = 200
}

resource "aws_iam_role" "notify" {
  name = "shop-notify"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "notify" {
  function_name = "shop-notify"
  role          = aws_iam_role.notify.arn
  handler       = "notify.handler"
  runtime       = "python3.12"
  filename      = "build/notify.zip"

  environment {
    variables = {
      SMTP_HOST     = "smtp.example.com"
      SMTP_PASSWORD = "example-only-smtp-password"
    }
  }
}

resource "aws_cloudwatch_log_group" "notify" {
  name = "/aws/lambda/shop-notify"
}
