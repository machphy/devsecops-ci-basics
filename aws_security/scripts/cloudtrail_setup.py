import argparse
import json
import logging
import sys

import boto3
from botocore.exceptions import ClientError


def create_s3_bucket(bucket_name, region=None):
    session = boto3.session.Session()
    s3 = session.client('s3', region_name=region)

    try:
        if region is None or region == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region},
            )

        logging.info('Created or verified S3 bucket: %s', bucket_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            logging.info('S3 bucket already exists and is owned by you: %s', bucket_name)
        else:
            logging.error('Unable to create S3 bucket: %s', exc)
            raise


def put_bucket_policy(bucket_name, account_id):
    policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AllowCloudTrailDelivery',
                'Effect': 'Allow',
                'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                'Action': 's3:GetBucketAcl',
                'Resource': f'arn:aws:s3:::{bucket_name}',
            },
            {
                'Sid': 'AllowCloudTrailPutObject',
                'Effect': 'Allow',
                'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                'Action': 's3:PutObject',
                'Resource': f'arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*',
                'Condition': {
                    'StringEquals': {
                        's3:x-amz-acl': 'bucket-owner-full-control'
                    }
                },
            },
        ],
    }

    s3 = boto3.client('s3')
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    logging.info('Applied bucket policy for CloudTrail delivery to %s', bucket_name)


def create_trail(trail_name, s3_bucket_name, is_multi_region=True, enable_log_file_validation=True):
    client = boto3.client('cloudtrail')

    try:
        client.create_trail(
            Name=trail_name,
            S3BucketName=s3_bucket_name,
            IsMultiRegionTrail=is_multi_region,
            EnableLogFileValidation=enable_log_file_validation,
        )
        logging.info('Created CloudTrail trail: %s', trail_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'TrailAlreadyExistsException':
            logging.info('CloudTrail trail already exists: %s', trail_name)
        else:
            logging.error('Unable to create CloudTrail trail: %s', exc)
            raise


def start_logging(trail_name):
    client = boto3.client('cloudtrail')
    client.start_logging(Name=trail_name)
    logging.info('Started logging for CloudTrail trail: %s', trail_name)


def enable_cloudwatch_integration(trail_name, log_group_arn, role_arn):
    client = boto3.client('cloudtrail')
    client.update_trail(
        Name=trail_name,
        CloudWatchLogsLogGroupArn=log_group_arn,
        CloudWatchLogsRoleArn=role_arn,
    )
    logging.info('Updated trail %s with CloudWatch Logs integration', trail_name)


def parse_args():
    parser = argparse.ArgumentParser(description='Create a CloudTrail trail and configure logging.')
    parser.add_argument('--trail-name', default='default-cloudtrail-trail', help='Name of the CloudTrail trail')
    parser.add_argument('--bucket-name', required=True, help='S3 bucket for CloudTrail logs')
    parser.add_argument('--region', default='us-east-1', help='AWS region for the S3 bucket')
    parser.add_argument('--account-id', required=True, help='AWS account ID to scope the bucket policy')
    parser.add_argument('--cloudwatch-group-arn', help='Optional CloudWatch Logs log group ARN')
    parser.add_argument('--cloudwatch-role-arn', help='IAM role ARN for CloudTrail to publish to CloudWatch Logs')
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    create_s3_bucket(args.bucket_name, region=args.region)
    put_bucket_policy(args.bucket_name, args.account_id)
    create_trail(args.trail_name, args.bucket_name)
    start_logging(args.trail_name)

    if args.cloudwatch_group_arn and args.cloudwatch_role_arn:
        enable_cloudwatch_integration(args.trail_name, args.cloudwatch_group_arn, args.cloudwatch_role_arn)

    logging.info('CloudTrail setup completed for trail %s', args.trail_name)


if __name__ == '__main__':
    main()
