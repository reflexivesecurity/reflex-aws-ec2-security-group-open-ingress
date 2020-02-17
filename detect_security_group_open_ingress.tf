provider "aws" {
  region = "us-east-1"
}

module "detect_security_group_open_ingress" {
  source           = "git@github.com:cloudmitigator/reflex.git//modules/cwe_lambda"
  rule_name        = "DetectSecurityGroupOpenIngress"
  rule_description = "Rule to check if AMI is modified to be public"

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "source": [
    "aws.ec2"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "CreateSecurityGroup",
      "AuthorizeSecurityGroupIngress"
    ]
  }
}
PATTERN


  function_name            = "DetectSecurityGroupOpenIngress"
  source_code_dir          = "${path.module}/source"
  handler                  = "detect_security_group_open_ingress.lambda_handler"
  lambda_runtime           = "python3.7"
  environment_variable_map = { SNS_TOPIC = module.detect_security_group_open_ingress.sns_topic_arn  }
  custom_lambda_policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:DescribeSecurityGroups"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF


  queue_name    = "DetectSecurityGroupOpenIngress"
  delay_seconds = 0

  target_id = "DetectSecurityGroupOpenIngress"

  topic_name = "DetectSecurityGroupOpenIngress"
  email      = var.email
}
