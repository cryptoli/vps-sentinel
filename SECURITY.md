# Security Policy

vps-sentinel is a defensive security project. Please do not publish exploitable security issues publicly before maintainers have had time to respond.

## Reporting

Open a private GitHub security advisory if available. If that is not possible, open an issue with minimal sensitive detail and ask for a private contact path.

## Scope

In scope:

- secret leakage in logs or notifications;
- unsafe parsing that can crash the daemon;
- unintended destructive behavior;
- privilege or file-permission mistakes in deployment scripts;
- vulnerabilities in notification or update paths.

Out of scope:

- requests to add exploit code;
- password brute-force features;
- third-party target scanning;
- stealth or evasion features.
