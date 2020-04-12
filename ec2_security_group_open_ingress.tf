module "ec2_security_group_open_ingress" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.7"
  rule_name        = "Ec2SecurityGroupOpenIngress"
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


  function_name            = "Ec2SecurityGroupOpenIngress"
  source_code_dir          = "${path.module}/source"
  handler                  = "ec2_security_group_open_ingress.lambda_handler"
  lambda_runtime           = "python3.7"
  environment_variable_map = { SNS_TOPIC = var.sns_topic_arn }
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


  queue_name    = "Ec2SecurityGroupOpenIngress"
  delay_seconds = 0

  target_id = "Ec2SecurityGroupOpenIngress"

  sns_topic_arn = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
