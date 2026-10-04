# PatchIQ-iA

## AI-Powered Security Code Review for GitHub Pull Requests

PatchIQ-iA is an automated security-focused code review system designed to analyze GitHub Pull Requests for potential security vulnerabilities.

The project combines deterministic static analysis with local AI-powered semantic analysis to identify security issues, validate AI-generated findings against the actual code changes, and publish structured security reviews directly to GitHub Pull Requests.

The central objective of PatchIQ-iA is to make security analysis a natural part of the Pull Request workflow while reducing false positives, unsupported findings, and AI hallucinations through evidence-based validation.

---

## Project Team

| Name | Registration Number |
|---|---|
| Ayush Kumar Singh | 25BCE11163 |
| Aditya Pandey | 25BCE11019 |
| Vishal Yadav | 25BCE11149 |
| Atharva Singh | 25BCE10984 |
| Krishna Nishad | 25BCE11329 |

---

## Abstract

Modern software development increasingly depends on rapid iteration and collaborative Git-based workflows. Pull Requests provide an effective mechanism for reviewing changes, but manually identifying security vulnerabilities in every change can be time-consuming and inconsistent.

PatchIQ-iA addresses this problem by integrating automated security analysis directly into the GitHub Pull Request lifecycle.

When a Pull Request event is received, the system securely validates the webhook, places the analysis task into a Redis-backed queue, retrieves the relevant code changes, performs deterministic security checks, and invokes a locally hosted AI model for semantic analysis where appropriate. AI-generated findings are subsequently validated against the actual Pull Request changes before they are included in the final security report.

This architecture combines the predictability of rule-based analysis with the contextual reasoning capabilities of local AI while maintaining an additional validation layer between AI output and the final GitHub report.

---

## Key Features

### Automated Pull Request Analysis

PatchIQ-iA can process GitHub Pull Request webhook events and initiate security analysis automatically.

### Secure Webhook Verification

Incoming GitHub webhook requests are verified using HMAC-SHA256 signatures before processing.

### Asynchronous Job Processing

Redis is used as an intermediate job queue. This separates webhook reception from the potentially longer security-analysis process.

### Deterministic Static Analysis

Known security patterns can be identified using deterministic checks without relying on an AI model.

### Local AI Security Analysis

Ollama is used to run a coding model locally for semantic security analysis.

### Candidate-Based AI Analysis

Instead of asking the AI model to identify unrestricted classes of vulnerabilities across the entire codebase, PatchIQ-iA first identifies relevant vulnerability candidates from the changed code.

### Evidence-Based Validation

AI findings are validated against the actual added lines of the Pull Request. Findings that cannot be supported by the changed code are rejected.

### Structured Findings

Validated findings can contain severity, reasoning, evidence, and remediation recommendations.

### Dockerized Deployment

The API, Redis queue, and worker can be orchestrated using Docker Compose.

### Local Inference

The architecture supports local AI inference through Ollama, reducing dependence on external inference APIs for the analysis stage.

---

## System Architecture

```text
                           GitHub Pull Request
                                    |
                                    | Webhook
                                    v
                       +-------------------------+
                       |       FastAPI API        |
                       |    Webhook Receiver      |
                       +------------+-------------+
                                    |
                                    | HMAC-SHA256
                                    | Verification
                                    v
                       +-------------------------+
                       |         Redis            |
                       |       Job Queue          |
                       +------------+-------------+
                                    |
                                    | PR Analysis Job
                                    v
                       +-------------------------+
                       |        Worker            |
                       |   Pull Request Engine    |
                       +------------+-------------+
                                    |
                         +----------+----------+
                         |                     |
                         v                     v
                +----------------+    +----------------------+
                | Static Analysis|    | Candidate Detection  |
                +--------+-------+    +----------+-----------+
                         |                       |
                         |                       v
                         |              +--------------------+
                         |              | Ollama / Local AI  |
                         |              | Semantic Analysis  |
                         |              +---------+----------+
                         |                        |
                         +------------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Finding Validation   |
                           | Evidence Verification|
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | GitHub Pull Request  |
                           |   Security Review    |
                           +----------------------+
```

---

## End-to-End Processing Flow

When a Pull Request event is received, PatchIQ-iA follows this pipeline:

1. GitHub sends a Pull Request webhook event.
2. FastAPI receives the incoming request.
3. The HMAC-SHA256 signature is verified.
4. Relevant Pull Request information is extracted.
5. A processing job is placed into the Redis queue.
6. The worker retrieves the queued job.
7. Pull Request changes are retrieved through the GitHub API.
8. Added lines from the Pull Request diff are extracted.
9. Deterministic static security checks are performed.
10. Potential AI vulnerability candidates are identified.
11. Relevant code is submitted to the local Ollama model.
12. AI output is parsed as structured data.
13. Findings are validated against supported vulnerability categories.
14. Evidence is checked against the actual Pull Request changes.
15. Invalid, unsupported, duplicated, or unsupported findings are rejected.
16. Validated findings are combined into a security review.
17. The final review is posted to the GitHub Pull Request.

---

## Security Analysis

PatchIQ-iA currently supports analysis of vulnerability categories including:

- Hardcoded Secrets
- Unsafe `eval()` / `exec()`
- Command Injection
- SQL Injection
- Path Traversal
- Insecure Deserialization
- Unsafe YAML Loading

The analysis architecture is intentionally layered.

### Layer 1: Static Detection

Deterministic checks identify known security-sensitive patterns in the changed code.

This provides predictable detection for vulnerability classes that can be recognized through established code patterns.

### Layer 2: Candidate Detection

The system determines whether a changed section of code represents a relevant candidate for deeper semantic analysis.

This limits unnecessary AI analysis and provides additional constraints on the model.

### Layer 3: Local AI Analysis

The candidate code is analyzed using a locally hosted coding model through Ollama.

The AI is expected to return structured security findings rather than unrestricted natural-language output.

### Layer 4: Evidence Validation

AI-generated findings are checked against the actual code added by the Pull Request.

This is a critical part of the architecture because an AI model may otherwise identify a vulnerability that is not actually present in the submitted change.

### Layer 5: Final Reporting

Only findings that pass the validation pipeline are included in the final Pull Request security review.

---

## Hallucination-Resistance Strategy

A major design consideration of PatchIQ-iA is preventing unsupported AI findings from being reported as genuine security vulnerabilities.

The validation pipeline uses several constraints:

- Supported vulnerability categories are explicitly controlled.
- AI output is expected in structured JSON format.
- Severity values are validated.
- Evidence must correspond to code introduced by the Pull Request.
- Findings without sufficient evidence can be rejected.
- Duplicate findings can be filtered.
- Invalid or malformed AI responses are not directly published.

This approach does not assume that an AI model is always correct. Instead, AI is treated as one component of a larger security-analysis pipeline.

---

## Technology Stack

| Technology | Role |
|---|---|
| Python 3.12 | Core application and processing logic |
| FastAPI | Webhook API |
| Redis | Asynchronous job queue |
| Ollama | Local AI inference |
| DeepSeek Coder | Current local code-analysis model |
| PyGithub | GitHub API integration |
| Docker | Application containerization |
| Docker Compose | Multi-service orchestration |
| ngrok | Local webhook tunneling |
| Git | Source-code version control |

---

## Project Structure

```text
patchiq-ia/
|
+-- app/
|   +-- __init__.py
|   +-- main.py
|   +-- processor.py
|   +-- worker.py
|
+-- tests/
|   +-- samples/
|   |   +-- vulnerable_code_sample.py
|   +-- test_ai.py
|
+-- tools/
|   +-- ngrok/
|       +-- ngrok.exe                 
|
+-- certs/
|   +-- <GitHub App private key>     
|
+-- .dockerignore
+-- .env.example
+-- .gitignore
+-- Dockerfile
+-- docker-compose.yml
+-- out.txt
+-- requirements.txt
+-- README.md
```

Sensitive local files such as `.env`, private keys, virtual environments, Python caches, and local executables are intentionally excluded from version control.

---

## Requirements

The development environment requires:

- Python 3.12 or later
- Git
- Docker Desktop
- Ollama
- A GitHub account
- A GitHub App configured for Pull Request webhooks
- ngrok for local webhook testing

---

## Configuration

Create a local environment file from the provided example:

```powershell
Copy-Item .env.example .env
```

Configure the required values:

```env
GITHUB_APP_ID=your_app_id
GITHUB_WEBHOOK_SECRET=your_webhook_secret
GITHUB_PRIVATE_KEY_PATH=./certs/your_private_key.pem
REDIS_HOST=redis
OLLAMA_HOST=http://host.docker.internal:11434
```

### Credential Protection

The following files must never be committed to the repository:

```text
.env
*.pem
*.key
```

The repository includes `.gitignore` rules to prevent these files from being tracked.

---

## Docker Deployment

Build and start the complete application:

```powershell
docker compose up -d --build
```

The Docker Compose configuration provides the following services:

```text
patchiq-api
patchiq-redis
patchiq-worker
```

Check service status:

```powershell
docker compose ps
```

View API logs:

```powershell
docker compose logs -f api
```

View worker logs:

```powershell
docker compose logs -f worker
```

Stop the application:

```powershell
docker compose down
```

When application source code changes require a rebuilt image, use:

```powershell
docker compose up -d --build
```

---

## Ollama Configuration

PatchIQ-iA uses Ollama for local model inference.

The current processor configuration uses:

```text
deepseek-coder:latest
```

The Docker worker communicates with the Ollama service running on the host through:

```text
http://host.docker.internal:11434
```

Ollama must therefore be running on the host machine when AI-based analysis is required.

---

## GitHub Webhook Testing

For local development, ngrok can expose the FastAPI service to GitHub.

Start the application:

```powershell
docker compose up -d api
```

Expose port `8000` through ngrok:

```powershell
.\tools\ngrok\ngrok.exe http 8000
```

The GitHub App webhook should point to:

```text
https://<ngrok-domain>/webhook
```

The application webhook endpoint is:

```text
POST /webhook
```

ngrok must remain active while testing external GitHub webhook events.

---

## Testing

PatchIQ-iA contains sample vulnerable code for testing the analysis pipeline.

Sample location:

```text
tests/samples/vulnerable_code_sample.py
```

Example:

```python
import os

# Mock vulnerable code for PatchIQ-iA testing

api_key = "THIS_IS_A_FAKE_TEST_SECRET_123456"

user_input = input("Enter something: ")

result = eval(user_input)

print(result)
```

The sample intentionally demonstrates:

- Hardcoded secret
- Unsafe `eval()`

The credential-like value is deliberately fake test data.

The current `tests/test_ai.py` file is also used as a mock script for exercising the AI-analysis path. It should not be interpreted as a comprehensive automated test suite.

---

## Sample Analyses and AI-Generated Results

Real PatchIQ-iA analysis examples will be maintained separately from the main application documentation.

The repository will contain an `examples/` directory with:

```text
examples/
|
+-- hardcoded_secret/
|   +-- vulnerable_code.py
|   +-- ai_output.md
|
+-- unsafe_eval/
|   +-- vulnerable_code.py
|   +-- ai_output.md
|
+-- combined_pr/
    +-- vulnerable_code.py
    +-- security_review.md
```

Each example will contain:

1. The vulnerable code submitted for analysis.
2. The relevant PatchIQ-iA AI output.
3. The resulting validated security findings.
4. The severity and reasoning generated by the analysis pipeline.
5. The recommended remediation where applicable.

These examples are intended to demonstrate the actual behavior of the system rather than theoretical capabilities.

Only sanitized test data and outputs that do not expose credentials, private keys, tokens, or other sensitive information should be included.

---

## Example Security Review

A validated PatchIQ-iA review can contain structured findings such as:

```text
## PatchIQ-iA Security Review

### High Severity

Hardcoded Secret

Reason:
A credential-like value was detected directly in the source code.

Recommendation:
Move secrets to environment variables or a secure secret-management system.

### High Severity

Unsafe eval()

Reason:
User-controlled input is passed to eval(), which may allow arbitrary
code execution.

Recommendation:
Avoid eval() and use a safe parser or explicit input validation.
```

The exact findings depend on the Pull Request being analyzed. The repository's `examples/` directory will contain actual outputs generated during project testing.

---

## Design Principles

### 1. Hybrid Security Analysis

PatchIQ-iA combines deterministic static analysis with AI-based semantic reasoning rather than relying entirely on an LLM.

### 2. Evidence-Based Reporting

Security findings must be supported by evidence from the actual Pull Request changes.

### 3. Validation Before Publication

AI-generated output passes through validation before being posted to GitHub.

### 4. Local AI Inference

The current architecture uses Ollama to perform model inference locally.

### 5. Asynchronous Processing

Redis separates webhook reception from Pull Request analysis, allowing security processing to occur asynchronously.

### 6. Separation of Responsibilities

The application separates webhook handling, queue management, worker processing, and security analysis into distinct components.

---

## Current Project Status

The current implementation provides:

- GitHub webhook integration
- HMAC-SHA256 webhook verification
- Redis-based asynchronous job processing
- Dockerized API and worker
- Static vulnerability detection
- AI candidate detection
- Local Ollama inference
- Structured AI output handling
- AI finding validation
- Evidence validation
- Duplicate finding filtering
- Automated GitHub Pull Request security reviews

---

## Future Scope

Potential future improvements include:

- Additional vulnerability detectors
- Broader programming-language support
- More comprehensive automated testing
- AI model benchmarking
- Security finding history
- Configurable severity policies
- Improved security dashboards
- CI/CD integration
- Production deployment
- Repository-level security analytics
- Improved false-positive reduction
- Historical vulnerability tracking

---

## Academic Project Team

### Ayush Kumar Singh
**Registration Number:** 25BCE11163

### Aditya Pandey
**Registration Number:** 25BCE11019

### Vishal Yadav
**Registration Number:** 25BCE11149

### Atharva Singh
**Registration Number:** 25BCE10984

### Krishna Nishad
**Registration Number:** 25BCE11329

---

## Project

**PatchIQ-iA**
git status
An AI-assisted security code review system designed to integrate automated security analysis directly into the GitHub Pull Request workflow.

The project focuses on combining deterministic security checks, local AI reasoning, asynchronous processing, and evidence-based validation into a single automated review pipeline.

---

## License

License information can be added when the project is prepared for public distribution.
