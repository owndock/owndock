# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub private vulnerability reporting for this repository. Do not open a public issue containing exploit details, credentials, private deployment information, or unredacted logs.

Include the affected version or commit, impact, reproduction steps, and any suggested mitigation. Maintainers will acknowledge the report, assess reachability and severity, and coordinate disclosure after a fix is available.

## Supported versions

OwnDock is under active development. Until the first stable release, security fixes are applied to the latest `main` branch only. Published support windows will be documented before stable releases are offered.

## Security boundaries

OwnDock is pre-release software that can connect to Docker Engines, private registries and managed hosts. A feature being present in the repository does not mean it is production ready. Before production use, review the current limitations in [the documentation index](docs/README.md), especially remote runtime, Agent revocation, network fault and terminal security status.

The following values are secrets and must never be committed, copied into images, included in issue reports, or written to application logs:

- MongoDB URI and bootstrap token;
- Agent CA private key and one-time enrollment token;
- Runtime Docker client private key and credential material;
- Registry password, Git Deploy Key or access token;
- Environment values resolved from `secret://` references;
- future Webhook signing secrets and Terminal connection tickets.

Configuration files contain only environment variable names or `secret://` references. Production deployments should inject secret values from a restricted secret manager, limit process and file access, and rotate material after suspected disclosure.

## Agent identity status

The current Agent enrollment implementation stores only a token hash, requires an Agent-generated CSR, issues a client-auth-only certificate, and prevents token replay. The separate TLS 1.3 control listener requires a verified client certificate and then checks the certificate URI, serial, fingerprint, expiry, revocation and fixed Host/instance against MongoDB. Its first typed command is `runtime.probe`: the wire payload accepts only a backend-resolved Runtime Target ID, uses bounded queues and stable result codes, and cannot carry a Docker endpoint or arbitrary shell command. Disabling a Host persists revocation, rejects later heartbeat/reconnect, cancels the current connection in the same Server process, and fails pending commands. The Agent process, command executor, certificate rotation and cross-process immediate disconnect in a future multi-Server topology are not implemented yet.

See [Agent security enrollment](docs/agent-enrollment.md) for the implemented flow and remaining boundary.

## Logs and reports

Do not attach raw access logs, traces, MongoDB exports, configuration dumps or terminal content without redaction. Reports should replace Organization, Project, Host, registry and network identifiers with synthetic values. OwnDock error responses and audit events must expose stable safe codes and metadata, not private keys, tokens, terminal payloads or raw infrastructure errors.
