""" Module for PublicAMIRule """

import json

import boto3

from reflex_core import AWSRule, subscription_confirmation


class Ec2SecurityGroupOpenIngress(AWSRule):
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

        self.offending_permissions = []
        for permission in response["SecurityGroups"][0]["IpPermissions"]:
            try:
                is_offending = False
                for ip_range in permission["IpRanges"]:
                    if ip_range["CidrIp"] == "0.0.0.0/0":
                        is_offending = True
                        is_compliant = False

                for ipv6_range in permission["Ipv6Ranges"]:
                    if ipv6_range["CidrIpv6"] == "::/0":
                        is_offending = True
                        is_compliant = False
                if is_offending:
                    self.offending_permissions.append(permission)

            except KeyError:
                continue

        return is_compliant

    def remediate(self):
        """ Fix the non-compliant resource """
        self.remove_open_ingress_rules()

    def remove_open_ingress_rules(self):
        self.client.revoke_security_group_ingress(
            GroupId=self.security_group_id, IpPermissions=self.offending_permissions
        )

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        message = f"Security group: {self.security_group_id} has open ingress IP ranges."
        if self.should_remediate():
            message += "Offending IP permissions have been removed."
        return message



def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = Ec2SecurityGroupOpenIngress(event_payload)
    rule.run_compliance_rule()
