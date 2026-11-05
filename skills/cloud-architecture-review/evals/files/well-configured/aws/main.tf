# Clean fixture: this folder must produce no finding.

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

resource "aws_db_instance" "orders" {
  identifier                  = "orders"
  engine                      = "postgres"
  instance_class              = "db.m6g.large"
  allocated_storage           = 100
  username                    = "orders"
  manage_master_user_password = true
  multi_az                    = true
  storage_encrypted           = true
  deletion_protection         = true
  backup_retention_period     = 14
  publicly_accessible         = false
  vpc_security_group_ids      = [aws_security_group.db.id]
}

resource "aws_dynamodb_table" "carts" {
  name                        = "carts"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "cart_id"
  deletion_protection_enabled = true

  attribute {
    name = "cart_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_s3_bucket" "receipts" {
  bucket = "orders-receipts-example"
}

resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "exports" {
  availability_zone = "eu-west-1a"
  size              = 200
  encrypted         = true
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = var.vpc_id

  ingress {
    description     = "PostgreSQL from the web tier only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

resource "aws_launch_template" "web" {
  name_prefix   = "web-"
  image_id      = "ami-00000000000000000"
  instance_type = "t3.large"
}

resource "aws_autoscaling_group" "web" {
  min_size            = 2
  max_size            = 6
  vpc_zone_identifier = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }
}

resource "aws_secretsmanager_secret" "smtp" {
  name = "orders/smtp"
}

resource "aws_iam_role" "notify" {
  name = "orders-notify"
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
  function_name = "orders-notify"
  role          = aws_iam_role.notify.arn
  handler       = "notify.handler"
  runtime       = "python3.12"
  filename      = "build/notify.zip"

  environment {
    variables = {
      SMTP_HOST       = "smtp.example.com"
      SMTP_SECRET_ARN = aws_secretsmanager_secret.smtp.arn
    }
  }
}

resource "aws_cloudwatch_log_group" "notify" {
  name              = "/aws/lambda/orders-notify"
  retention_in_days = 30
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "orders-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  evaluation_periods  = 3
  period              = 300
  statistic           = "Average"
}
