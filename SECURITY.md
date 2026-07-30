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

## Login protection status

Local login uses Argon2id password verification and stores only bearer-token hashes in MongoDB. Syntactically valid email addresses share a MongoDB-backed attempt window across Server instances; the key is a SHA-256 hash of the normalized email, and successful authentication clears it. The default fifth attempt closes a 15-minute window, so later requests receive `429 login_rate_limited` and `Retry-After` without revealing whether the account exists. Invalid or unknown credentials use the same public `401` response and unknown users perform a dummy Argon2id verification. MongoDB TTL removes expired attempt records. A successful login keeps only the configured number of newest active sessions, defaulting to ten. Authenticated users can list safe metadata for their own sessions and revoke one by ID; ownership is enforced in the delete query, token hashes are never returned, and revocation is committed with its audit event.

This account-level guard does not replace source-IP, connection or installation-wide limits at the trusted ingress. Production deployments must still configure rate and connection limits in the reverse proxy or WAF. User management, administrator-wide session control and Project membership revocation are not implemented yet.

## Agent identity status

The current Agent enrollment implementation stores only a token hash, requires an Agent-generated CSR, issues a client-auth-only certificate, and prevents token replay. The separate TLS 1.3 control listener requires a verified client certificate and then checks the certificate URI, serial, fingerprint, expiry, revocation and fixed Host/instance against MongoDB. Enrollment capabilities form an identity grant: a later hello may advertise only a subset, and every new typed command is checked against the authenticated connection before queueing. The Agent process requires local certificate files, rejects loose private-key permissions and symlinks, disables HTTP proxy use and redirects, and reconnects with bounded jittered backoff. Typed commands are limited to backend-resolved runtime probe and Docker deployment operations; they use bounded queues and stable result codes, and cannot carry a Docker endpoint or arbitrary shell command. Remote cutover is split into candidate staging, an authoritative Server-side MongoDB lease/cutover-fence check, and activation. The Agent executor accepts only a trusted local absolute Unix Socket path. Agent disk state separates an evictable safe-result cache from a non-evicting, fail-closed deployment-slot cutover watermark; both use restricted atomic files. The watermark contains only a stable container slot, Deployment ID and sequence. Neither file stores registry authorization, resolved environment secrets, target identifiers, complete commands, or raw Docker errors. Disabling a Host persists revocation, rejects later heartbeat/reconnect, cancels the current connection in the same Server process, and fails pending commands. Automated Agent installation/enrollment, certificate rotation, lifecycle-aware watermark garbage collection, real multi-host network-fault validation, and cross-process immediate disconnect in a future multi-Server topology are not implemented yet.

See [Agent security enrollment](docs/agent-enrollment.md) for the implemented flow and remaining boundary.

## Runtime inventory status

The Runtime Inventory domain and MongoDB repository store only an OwnDock-defined projection of Container, Image, Network and Volume data. The model has no raw Docker Inspect, environment value, registry authorization, host mount source or raw Docker error field. The Docker List mapper omits Volume mountpoints/options/status and accepts only three exact, structured ownership-candidate labels; those labels do not directly grant managed or Project access. Transport chunks have exact encoded byte and item limits. A new observation is invisible until every declared chunk is committed and the current generation is switched in a MongoDB transaction. MongoDB allocates a monotonic generation per Runtime Target, so stale observations cannot replace newer state even when Server clocks differ. Abandoned open observations expire after two hours.

The reusable Docker reader, safe mapper, direct persistence flow and Agent prepare/pull/release transport are implemented. Agent snapshots are memory-only, bounded to two snapshots and 32 MiB each, expire after ten minutes, and bypass both durable Agent results and the Server completed-result cache. Runtime Target source/credential wiring and scheduling, public query authorization and full adversarial system tests are not implemented. No caller should treat these components as permission to persist arbitrary Docker JSON. See [Docker Runtime Inventory](docs/runtime-inventory.md).

## Logs and reports

Do not attach raw access logs, traces, MongoDB exports, configuration dumps or terminal content without redaction. Reports should replace Organization, Project, Host, registry and network identifiers with synthetic values. OwnDock error responses and audit events must expose stable safe codes and metadata, not private keys, tokens, terminal payloads or raw infrastructure errors.
