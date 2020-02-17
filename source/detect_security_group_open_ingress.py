""" Module for PublicAMIRule """

import json

import boto3

from reflex_core import AWSRule


class SecurityGroupOpenIngressRule(AWSRule):
    """ AWS rule for ensuring non-public AMIs """

    client = boto3.client("ec2")

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required data from the CloudWatch event """
        self.raw_event = event
        self.event_name = event["detail"]["eventName"]
        if self.event_name == "AuthorizeSecurityGroupIngress":
            self.security_group_id = event["detail"]["requestParameters"]["groupId"]
        elif self.event_name == "CreateSecurityGroup":
            self.security_group_id = event["detail"]["responseElements"]["groupId"]

    def resource_compliant(self):
        is_compliant = True
        response = self.client.describe_security_groups(
            GroupIds=[self.security_group_id]
        )

        for permission in response["SecurityGroups"][0]["IpPermissions"]:
            try:
                for ip_range in permission['IpRanges']:
                    if ip_range["CidrIp"] == "0.0.0.0/0":
                        is_compliant = False

                for ipv6_range in permission['Ipv6Ranges']:
                    if ipv6_range["CidrIpv6"] == "::/0":
                        is_compliant = False
            except KeyError:
                continue

        return is_compliant

    def remediate(self):
        pass

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"Security group: {self.security_group_id} has open ingress IP ranges."


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    rule = SecurityGroupOpenIngressRule(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
