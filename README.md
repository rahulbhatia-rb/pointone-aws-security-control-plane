# PointOne AWS Security Control Plane

Independent proof-of-concept inspired by PointOne's public infrastructure-security role.

The role is not a checkbox-security position. It calls for architectural ownership across IAM,
multi-account AWS, networking, KMS/secrets, blast-radius containment, immutable logging,
incident response, and scale/cost tradeoffs.

This repository turns those requirements into an executable **security deployment gate** plus
reference Terraform patterns and incident-response documentation.

It does **not** represent PointOne's private infrastructure.

## What it demonstrates

A service/infrastructure contract is evaluated before production rollout.

The gate checks for:

- wildcard IAM permissions
- risky cross-account trust
- missing permission boundary
- public database exposure
- public administrative ingress
- mutable audit logging
- missing KMS separation
- plaintext/unmanaged secrets
- unrestricted egress
- missing workload identity
- missing Lambda reserved concurrency
- unsafe SQS retry/DLQ configuration
- RDS scaling/connection guardrails
- missing incident-response ownership
- weak environment/account isolation

## Example

```bash
go test ./...
go vet ./...
go run ./cmd/securitygate -contract examples/safe-service.json
```

Expected:

```json
{
  "allowed": true
}
```

## Why this maps to PointOne

PointOne's public role emphasizes:

- least-privilege IAM
- permission boundaries and SCP strategy
- reduced attack surface
- secrets and KMS segmentation
- threat modeling
- blast-radius containment
- immutable/auditable logging
- incident-response playbooks
- multi-account AWS
- VPC / PrivateLink / Security Groups
- Lambda / SQS scaling
- RDS scaling
- security-aware cost optimization

This prototype directly models those responsibilities.

## Security workflow

```text
IaC / service change
        |
        v
 securitygate
   |      |      |      |
 IAM   network  logs  resilience
   |      |      |      |
   +------+------+------+
        |
   allow / deny
        |
        v
 review + deploy evidence
```

## Repository layout

```text
cmd/securitygate/          executable policy gate
internal/policy/           security rules
examples/                  safe and unsafe contracts
terraform/iam-boundaries/  permission-boundary reference
terraform/immutable-logging/ centralized audit-log reference
terraform/private-network/ private-service reference
docs/threat-model.md       attack paths and mitigations
docs/incident-response.md  incident playbooks
docs/blast-radius.md       account / tenant containment
docs/30-60-90.md           security roadmap
.github/workflows/         CI security validation
```

## Threat model focus

The important failure modes are not "is GuardDuty on?"

They are questions such as:

- Can one compromised workload role assume a broader role?
- Can a developer accidentally create a trust policy that crosses the intended boundary?
- Can one tenant's workload reach another tenant's data path?
- Can an attacker destroy or rewrite audit evidence?
- Can a Lambda concurrency spike exhaust RDS?
- Can poisoned/replayed SQS messages trigger duplicate legal/billing mutations?
- Can a secret compromise cross environment boundaries?
- Can a production incident be contained to one account/service/customer boundary?

## IAM model

A production design should combine:

1. Organizations / accounts for hard boundaries
2. SCPs for organization-level invariants
3. permission boundaries for delegated role creation
4. least-privilege identity/resource policies
5. explicit trust relationships
6. short-lived STS credentials
7. workload identity instead of static keys

The gate rejects wildcard IAM actions and missing boundaries for sensitive workloads.

## Immutable logging

The reference design assumes a dedicated logging/security account with:

- organization CloudTrail
- central S3 bucket
- Object Lock / retention controls where required
- tightly scoped write path
- separate KMS key
- no application-role delete permissions

## Lambda / SQS / RDS resilience

Security and reliability interact.

The gate requires:
- Lambda reserved concurrency for sensitive async paths;
- SQS DLQ and bounded receives;
- visibility timeout declaration;
- idempotency for mutation workers;
- RDS connection-budget awareness.

This prevents a security event or traffic spike from becoming a platform-wide outage.

## Cost and isolation

More isolation is not automatically better.

Separate accounts/clusters/DBs improve blast-radius containment but increase cost and operational
overhead. The architecture should use the strongest isolation where the data/customer/risk boundary
justifies it, then share lower-risk infrastructure intentionally.

## Disclaimer

Independent engineering prototype based only on PointOne's public role and public product/security information.
