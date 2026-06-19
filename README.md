# DevSecOps CI Basics

A hands-on repository for learning and implementing DevSecOps practices in Continuous Integration (CI) pipelines.

## Overview

This project demonstrates how to integrate security into the software development lifecycle by automating security checks within CI workflows.

Topics covered include:

* Secure coding practices
* Static Application Security Testing (SAST)
* Dependency vulnerability scanning
* Secrets detection
* CI/CD pipeline security
* API security testing
* Infrastructure security basics

## Project Structure

```text
.
├── scripts/
│   ├── api_security/
│   └── ...
├── .github/
│   └── workflows/
├── README.md
└── requirements.txt
```

## Prerequisites

* Python 3.12+
* Git
* GitHub Account
* Linux/macOS/WSL (recommended)

## Installation

Clone the repository:

```bash
git clone https://github.com/machphy/devsecops-ci-basics.git
cd devsecops-ci-basics
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running Tests

```bash
pytest
```

## Security Checks

Examples of security controls that can be integrated:

* Bandit for Python SAST
* Safety or pip-audit for dependency scanning
* Gitleaks for secret detection
* Trivy for container and filesystem scanning
* Custom Go secret scanning tool

Example:

```bash
bandit -r .
pip-audit
```

## New Demo: Bash + Go Secret Scanning

A simple Bash wrapper runs the Go secret scanner against a file in the repository.

```bash
export SCAN_FILE=README.md
bash scripts/secret_scan_demo.sh
```

The Go tool is located at `go_tools/secret_scanner`, and it detects secrets using regex patterns for AWS keys, generic API keys, and JWTs.

## CI/CD Integration

This repository can be used to practice:

* Automated testing
* Security scanning
* Pull request validation
* Secure deployment workflows

## Learning Goals

* Understand DevSecOps fundamentals
* Shift security left in the development process
* Automate security validation
* Build secure CI/CD pipelines

## Contributing

Contributions, improvements, and learning exercises are welcome.

## License

This project is intended for educational and learning purposes.
