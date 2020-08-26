module "cwe" {
  source      = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe?ref=v2.0.1"
  name        = "Ec2SecurityGroupOpenIngress"
  description = "Rule to check if AMI is modified to be public"

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
}
