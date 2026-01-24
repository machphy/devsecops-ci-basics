# Security Principles

## CIA Triad
The CIA triad represents the core objectives of information security:
- Confidentiality: Prevent unauthorized access to data
- Integrity: Prevent unauthorized modification of data
- Availability: Ensure systems remain accessible

## Principle of Least Privilege
Users and systems should be granted only the minimum permissions required to perform their tasks.

## Defense in Depth
Security should be implemented in multiple layers so that failure of one control does not compromise the system.

## Zero Trust
Zero Trust follows the principle of “never trust, always verify,” requiring continuous authentication and authorization.

## Secure by Design
Security should be integrated from the design phase rather than added after deployment.

## DevSecOps Mapping
DevSecOps applies these principles by embedding security controls directly into CI/CD pipelines.
## Practical Mapping
- Confidentiality: Secrets leaked in repositories break confidentiality
- Integrity: Unauthorized code changes break integrity
- Availability: Failed deployments impact availability

## Least Privilege in DevSecOps
CI/CD pipelines should use scoped tokens so that a compromise does not lead to full system access.
