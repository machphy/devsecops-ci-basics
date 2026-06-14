# AWS S3 Security — CC Exam Entry

- Date: 2026-06-09
- Author: rajeev

## Title

AWS S3 security controls and risk mitigation

## Question

What are the key security controls for AWS S3 buckets, and how do they help prevent accidental data exposure?

## Answer / Notes

- Use IAM policies and bucket policies to enforce least privilege for principals.
- Enable Block Public Access on all buckets unless public access is explicitly required.
- Enforce encryption at rest with SSE-S3, SSE-KMS, or client-side encryption.
- Enable versioning to support recovery from accidental deletion or ransomware.
- Configure S3 server access logging and CloudTrail for auditing and monitoring bucket activity.
- Avoid using ACLs for access control unless absolutely necessary.
- Do not store sensitive secrets or credentials in buckets.
- Apply automated checks with AWS Config rules, Cloud Custodian, or CI/CD scanning for misconfigurations.

---

Created by assistant — edit as needed.
