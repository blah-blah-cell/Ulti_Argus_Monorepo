# Security policy

## Supported branch

Security fixes target the current `main` branch. This project is experimental and has no long-term-support release yet.

## Reporting a vulnerability

Please use GitHub's private **Security advisories → Report a vulnerability** flow for this repository. Do not open a public issue containing exploit details, credentials, packet captures, or private network data.

Include the affected commit, reproduction steps, impact, and a minimal sanitized proof of concept. Maintainers will acknowledge a report when it has been reviewed; no fixed response-time SLA is promised.

## Deployment assumptions

- The API binds to loopback by default.
- State-changing and traffic-detail APIs require a local session token or `X-API-Key`.
- CORS is restricted to configured origins.
- No trained detection model or automated enforcement policy is distributed.
- Missing components fail closed.

Do not expose the development server directly to the Internet. Put any remote deployment behind a maintained reverse proxy, TLS, authentication, host firewall, and least-privilege service account. Packet capture privileges should be separated from the web process where possible.

## Sensitive data

PCAP/PCAPNG/ETL files, model artifacts, datasets, `.env` files, and private keys must never be committed. If sensitive material enters Git history, deleting the working-tree file is not sufficient; rotate affected credentials and purge repository history before disclosure.
