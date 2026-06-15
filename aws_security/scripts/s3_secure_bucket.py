"""AWS S3 security helper script.

This script demonstrates how to harden an S3 bucket by enabling
public access blocking, default encryption, and bucket versioning.
"""

import argparse
import logging

import boto3
from botocore.exceptions import ClientError


def enable_public_access_block(bucket_name):
    s3 = boto3.client('s3control')
    account_id = boto3.client('sts').get_caller_identity()['Account']

    config = {
        'AccountId': account_id,
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True,
        },
    }

    try:
        s3.put_public_access_block(**config)
        logging.info('Enabled public access block for account %s', account_id)
    except ClientError as exc:
        logging.error('Failed to enable public access block: %s', exc)
        raise


def enable_bucket_encryption(bucket_name):
    s3 = boto3.client('s3')
    encryption_configuration = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }
        ]
    }

    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_configuration,
        )
        logging.info('Enabled default SSE-S3 encryption for bucket %s', bucket_name)
    except ClientError as exc:
        logging.error('Failed to enable bucket encryption: %s', exc)
        raise


def enable_bucket_versioning(bucket_name):
    s3 = boto3.client('s3')
    try:
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'},
        )
        logging.info('Enabled versioning for bucket %s', bucket_name)
    except ClientError as exc:
        logging.error('Failed to enable bucket versioning: %s', exc)
        raise


def parse_args():
    parser = argparse.ArgumentParser(description='Harden an S3 bucket with public access block and defaults.')
    parser.add_argument('--bucket-name', required=True, help='Name of the S3 bucket to harden')
    parser.add_argument('--skip-account-block', action='store_true', help='Skip account-level public access block configuration')
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if not args.skip_account_block:
        enable_public_access_block(args.bucket_name)

    enable_bucket_encryption(args.bucket_name)
    enable_bucket_versioning(args.bucket_name)

    logging.info('S3 bucket hardening completed for %s', args.bucket_name)


if __name__ == '__main__':
    main()
