#!/usr/bin/env python
# AWS security group module
# Reference: http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.SecurityGroup.ip_permissions

import boto3
import sys


class Client(object):

    def __init__(self, sg_id):
        self.id = sg_id
        self.ip_permissions = boto3.resource('ec2', region_name='ap-southeast-2', api_version='2016-04-01')\
            .SecurityGroup(self.id).ip_permissions

    def show_ingress(self):
        return self.ip_permissions

    def add_ingress(self, **kwargs):
        return boto3.resource('ec2', region_name='ap-southeast-2', api_version='2016-04-01')\
            .SecurityGroup(self.id).authorize_ingress(**kwargs)

    def remove_ingress(self, **kwargs):
        return boto3.resource('ec2', region_name='ap-southeast-2', api_version='2016-04-01') \
            .SecurityGroup(self.id).revoke_ingress(**kwargs)

