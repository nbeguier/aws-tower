#!/usr/bin/env python
"""
Scan library

Copyright 2020-2023 Leboncoin
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
Updated by Fabien MARTINEZ (fabien.martinez@adevinta.com)
Copyright 2023-2024 Nicolas BEGUIER
Licensed under the Apache License, Version 2.0
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
import logging

import libs.asset_type_apigw as apigw
import libs.asset_type_cf as cf
import libs.asset_type_ec2 as ec2
import libs.asset_type_eks as eks
import libs.asset_type_elb as elb
import libs.asset_type_iam_group as iam
import libs.asset_type_lightsail as lightsail
import libs.asset_type_mq as mq
import libs.asset_type_rds as rds
import libs.asset_type_route53 as r53
import libs.asset_type_s3_group as s3
import libs.asset_type_vpc as vpc

# Debug
# from pdb import set_trace as st

LOGGER = logging.getLogger('aws-tower')

def get_raw_data(boto_session, meta_types, cache, console):
    """
    Returned raw data and authorization failure for logging
    """
    authorizations = {
        'apigw': True,
        'cloudfront': True,
        'ec2': True,
        'eks': True,
        'elb': True,
        'iam': True,
        'lightsail': True,
        'mq': True,
        'rds': True,
        's3': True,
        'route53': True,
        'vpc': True
    }
    raw_data = {}

    raw_data, authorizations = ec2.get_raw_data(
        raw_data,
        authorizations,
        boto_session,
        cache,
        console)

    if 'APIGW' in meta_types:
        raw_data, authorizations = apigw.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'CLOUDFRONT' in meta_types:
        raw_data, authorizations = cf.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'EKS' in meta_types:
        raw_data, authorizations = eks.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'ELB' in meta_types:
        raw_data, authorizations = elb.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'LIGHTSAIL' in meta_types:
        raw_data, authorizations = lightsail.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'MQ' in meta_types:
        raw_data, authorizations = mq.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'RDS' in meta_types:
        raw_data, authorizations = rds.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'S3' in meta_types:
        raw_data, authorizations = s3.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'VPC' in meta_types:
        raw_data, authorizations = vpc.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    if 'EC2' in meta_types or 'ELB' in meta_types:
        raw_data, authorizations = r53.get_raw_data(
            raw_data,
            authorizations,
            boto_session,
            cache,
            console)

    return raw_data, authorizations

def log_authorization_errors(authorizations, console):
    """
    Print authorizations errors during scan
    """
    if not console:
        LOGGER.critical(f'A "False" suggest that something fail, too few authorizations?: {authorizations}')
    else:
        for auth in authorizations:
            if not authorizations[auth]:
                console.print(f'[red]Error scannig [bold]{auth}[/bold], maybe not enough permissions...')

def aws_scan(
    boto_session,
    cache,
    iam_action_passlist=[],
    iam_rolename_passlist=[],
    public_only=False,
    meta_types=[],
    name_filter='',
    console=None):
    """
    SCAN AWS
    """
    raw_data, authorizations = get_raw_data(boto_session, meta_types, cache, console)

    assets = []

    if 'APIGW' in meta_types:
        assets, authorizations = apigw.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            public_only,
            boto_session,
            name_filter,
            cache,
            console)

    if 'CLOUDFRONT' in meta_types:
        assets, authorizations = cf.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            cache,
            console)

    if 'EC2' in meta_types:
        assets, authorizations = ec2.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            boto_session,
            public_only,
            cache,
            console)

    if 'EKS' in meta_types:
        assets, authorizations = eks.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            cache,
            console)

    if 'ELB' in meta_types:
        assets, authorizations = elb.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'IAM' in meta_types:
        assets, authorizations = iam.parse_raw_data(
            assets,
            authorizations,
            boto_session,
            iam_action_passlist,
            iam_rolename_passlist,
            name_filter,
            cache,
            console)

    if 'LIGHTSAIL' in meta_types:
        assets, authorizations = lightsail.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'MQ' in meta_types:
        assets, authorizations = mq.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'RDS' in meta_types:
        assets, authorizations = rds.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'S3' in meta_types:
        assets, authorizations = s3.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'VPC' in meta_types:
        assets, authorizations = vpc.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            name_filter,
            public_only,
            cache,
            console)

    if 'EC2' in meta_types or 'ELB' in meta_types:
        assets, authorizations = r53.parse_raw_data(
            assets,
            authorizations,
            raw_data,
            cache,
            console)

    if 'EC2' in meta_types and 'IAM' in meta_types:
        assets, authorizations = ec2.parse_iam_instance_profile(
            assets,
            authorizations,
            raw_data,
            console)

    log_authorization_errors(authorizations, console)

    return assets
