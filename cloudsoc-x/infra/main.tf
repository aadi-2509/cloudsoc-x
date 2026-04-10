# infra/main.tf
# CloudSOC-X infrastructure — Kinesis + Lambda + OpenSearch + SNS
#
# Prerequisites:
#   - AWS CLI configured (aws configure)
#   - Terraform >= 1.4
#
# Usage:
#   terraform init
#   terraform plan -var="alert_email=you@example.com"
#   terraform apply -var="alert_email=you@example.com"

terraform {
  required_version = ">= 1.4"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "project_name" {
  default = "cloudsoc-x"
}

variable "alert_email" {
  description = "Email address to receive critical/high alerts"
  type        = string
}

variable "environment" {
  default = "dev"
}

# ---------------------------------------------------------------------------
# Kinesis Data Stream — receives CloudTrail + GuardDuty events
# ---------------------------------------------------------------------------

resource "aws_kinesis_stream" "events" {
  name             = "${var.project_name}-events"
  shard_count      = 1
  retention_period = 24

  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# SNS Topic — alert notifications
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# IAM Role for Lambda
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "lambda" {
  name = "cloudsoc-lambda-policy"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords", "kinesis:GetShardIterator",
          "kinesis:DescribeStream", "kinesis:ListShards",
        ]
        Resource = aws_kinesis_stream.events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["es:ESHttpPut", "es:ESHttpPost", "es:ESHttpGet"]
        Resource = "${aws_opensearch_domain.alerts.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "detector" {
  function_name = "${var.project_name}-detector"
  role          = aws_iam_role.lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = 60
  memory_size   = 256

  # You need to zip and upload the code first:
  # zip -r lambda_package.zip src/ lambda/ -x "**/__pycache__/*"
  filename         = "lambda_package.zip"
  source_code_hash = filebase64sha256("lambda_package.zip")

  environment {
    variables = {
      OPENSEARCH_ENDPOINT = "https://${aws_opensearch_domain.alerts.endpoint}"
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
      AWS_DEFAULT_REGION  = var.aws_region
      OPENSEARCH_INDEX    = "cloudsoc-alerts"
    }
  }

  tags = local.common_tags
}

resource "aws_lambda_event_source_mapping" "kinesis" {
  event_source_arn  = aws_kinesis_stream.events.arn
  function_name     = aws_lambda_function.detector.arn
  starting_position = "LATEST"
  batch_size        = 100
}

# ---------------------------------------------------------------------------
# OpenSearch Domain
# ---------------------------------------------------------------------------

resource "aws_opensearch_domain" "alerts" {
  domain_name    = "${var.project_name}-alerts"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
    volume_type = "gp3"
  }

  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# Locals
# ---------------------------------------------------------------------------

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "kinesis_stream_name" {
  value = aws_kinesis_stream.events.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "opensearch_endpoint" {
  value = aws_opensearch_domain.alerts.endpoint
}

output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}
