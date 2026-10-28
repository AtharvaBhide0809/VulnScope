# VulnScope

VulnScope is an experimental, **rule-based agentic network security scanner** written in Python. It explores how automated security checks can respond to earlier observations while respecting defined access restrictions.

## Overview

The agent requests TCP scans of authorised localhost ports. If it finds an open port commonly associated with HTTP, it may request a follow-up HTTP security-header check; otherwise, it records why it stopped.

The agent proposes actions, while ScopePolicy determines whether they are authorised and ScanExecutor enforces those restrictions. Requests pass through `ScopePolicy`, which checks the target, port, action and timeout. Results are analysed and saved in timestamped JSON reports with decisions and audit records.

## Current Features

- **TCP scanning:** Reports `OPEN`, `CLOSED`, `UNKNOWN` or `ERROR`, plus response time.
- **Service identification:** Suggests services using common port mappings, with low confidence.
- **Preliminary risk analysis:** Flags selected configurations for review, without claiming confirmed vulnerabilities.
- **HTTP inspection:** Checks for missing `Content-Security-Policy`, `X-Content-Type-Options` and `Referrer-Policy` headers.
- **Rule-based agent:** Chooses HTTP follow-ups based on TCP observations rather than running every check unconditionally.
- **Scope enforcement:** Restricts targets, ports, actions, timeouts and cumulative approved attempts.
- **Explicit sessions:** Multiple scan runs share an action budget; each run receives its own audit events.
- **JSON reporting:** Saves observations, findings, agent decisions and policy authorisation records.
- **Testing:** 39 automated unit and integration tests passed in the verified development baseline.

## Architecture

The components and their responsibilities are listed below:

- **agent/controller.py**  Selects follow-up actions and records reasoning.
- **security/policy.py**  Defines and validates the authorised scope.
- **security/executor.py**  Enforces policy, manages sessions and dispatches approved actions.
- **scanner/**  Implements TCP connections and HTTP header checks.
- **analysis/**  Suggests services and preliminary risks.
- **reporting/**  Builds and saves JSON reports.
- **tests/**  Checks behaviour, denials, session limits and integration.
- **main.py / demo.py**  Runs the scanner / demonstrates security boundaries.

**Workflow:** agent → policy-controlled executor → scanning tool → analysis → JSON report. The executor keeps session-wide limits and logs, while reports contain run-specific audit events.

## Running VulnScope

Requires Python 3.11+; the existing functionality uses only the Python standard library. On Windows, open PowerShell in the project directory:

```powershell
cd "$HOME\Documents\VulnScope"
python -m http.server 8000 --bind 127.0.0.1
```

Leave the local server running. In a second PowerShell terminal:

```powershell
cd "$HOME\Documents\VulnScope"
python main.py
```

The agent should detect an open port 8000 and request an HTTP check. It saves a report under `reports/`. Stop the server with **Ctrl+C**. To demonstrate permitted and denied requests, run `python demo.py` with the server running.

## Running Tests

From the project root, run:

```powershell
python -m unittest discover -s tests -v
```

The suite covers TCP outcomes, HTTP inspection, scope restrictions, agent decisions, session lifecycle, JSON reporting and integration scenarios. Network functions are mocked in many tests so denied actions can be checked without contacting external hosts. Manual localhost checks complement the automated suite.

## Reports and Evidence

Reports contain `schema_version`, `generated_at`, `target`, `observations`, `findings`, `agent_decisions`, `policy_audit_log` and summary counts. 'Authorised' means permitted, not necessarily successfully executed; errors and outcomes must be read separately.

Generated files under `reports/` are excluded from Git to avoid accidentally publishing scan data. Any public sample should be synthetic or sanitised.

A synthetic example of the JSON output is available in `examples/sample_report.json`.

## Safety and Scope

By default, `ScopePolicy` permits only target `127.0.0.1`, ports `8000` and `8080`, actions `tcp_connect` and `http_headers`, a maximum requested timeout of 2 seconds, and 20 approved action attempts per session. Requests outside these restrictions are denied before the executor invokes scanning functions.

Only assess systems you are explicitly authorised to test. **These are application-level controls, not a security sandbox:** unrestricted Python, shell or network access could bypass the executor. A future LLM must use restricted tools and additional isolation.

## Limitations

- Port-based service identification is not verified fingerprinting; an open port is not proof of a vulnerability.
- Timeouts are reported as `UNKNOWN`, and missing HTTP headers are observations rather than confirmed exploits.
- HTTP inspection uses plain HTTP at `/`; it does not assess TLS, follow redirects or validate header values.
- The agent uses fixed rules, not an LLM; there is no CVE matching, payload generation or exploitation.
- Audit records are useful for review, but are not tamper-proof or forensic-grade.

## Future Development

Possible extensions include service fingerprinting, HTTPS/TLS checks, richer reporting and verified CVE intelligence. Longer-term research could use an LLM such as Hermes with narrowly authorised Nmap/Nuclei tools and isolated, non-destructive payload validation. **These are future goals, not features of v1.0.**

## Development Approach

VulnScope is a personal cybersecurity project developed to explore agentic security scanning, access control and responsible automation.

I directed the project's development by defining its objectives, implementing and testing its components, investigating technical issues, and evaluating architectural decisions. Particular attention was given to ensuring that the agent's decisions remained subject to independently enforced security restrictions.

Generative AI was used to assist with Python implementation, test development, documentation and understanding unfamiliar concepts. Throughout development, I worked to verify the suggested implementations, understand their behaviour, and make informed decisions about the project's design and limitations.

This approach allowed me to develop my practical programming, testing and security engineering knowledge while building a functioning rule-based agentic vulnerability scanner.
