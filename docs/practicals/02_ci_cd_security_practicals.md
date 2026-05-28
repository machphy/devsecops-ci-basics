## Practical: CI/CD Secret Leak Prevention

This practical shows how CI/CD pipelines can enforce security before code reaches production.

### What is CI/CD?
- CI (Continuous Integration): automatically build and test code after every change.
- CD (Continuous Delivery/Deployment): automatically prepare or deploy code only when all checks pass.
- A pipeline is the automated workflow that runs these steps.

### What this repository already includes
- `.github/workflows/main.yml` - a GitHub Actions workflow that runs a secret scan with Gitleaks.
- `.github/workflows/pipeline-security.yml` - a GitHub Actions workflow that runs Bandit, Safety, and a secret environment check.

### Hands-on demo
A simple local demo script has been added at `scripts/ci_cd_demo.sh`.

To use it:
1. Open a terminal in the repo root.
2. Set a demo secret:
   ```bash
   export API_KEY=demo_value
   ```
3. Run the demo:
   ```bash
   bash scripts/ci_cd_demo.sh
   ```

### Pipeline steps covered
- Check that required secrets are provided.
- Run static code analysis with `bandit`.
- Scan dependencies for known vulnerabilities with `safety`.
- Fail fast when a problem is found.

### Why this matters
- It keeps insecure code from advancing.
- It prevents leaked secrets from being used in automation.
- It helps shift security left into the development workflow.

### Next learning steps
- Open the workflow files under `.github/workflows/` and read how each step is defined.
- Learn about GitHub Actions events like `push` and `pull_request`.
- Add more checks, such as tests or a container image scan.
