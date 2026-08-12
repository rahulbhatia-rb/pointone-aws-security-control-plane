# Threat Model

## High-value assets
- legal billing/timekeeping data
- customer documents and metadata
- credentials and tokens
- audit evidence
- production infrastructure control plane

## Primary attack paths

### Compromised workload role
Risk: attacker uses a Lambda/ECS/EKS role to assume broader privileges.

Controls:
- narrow trust policies
- permission boundaries
- SCP invariants
- session duration limits
- explicit cross-account trust
- CloudTrail anomaly detection

### Cross-tenant data access
Risk: authorization bug or infrastructure misconfiguration crosses a customer boundary.

Controls:
- account/VPC/data-layer segmentation proportional to risk
- tenant-scoped authorization context
- least-privilege data access
- KMS segmentation
- traceable access paths

### Audit-log destruction
Risk: attacker deletes the evidence required to investigate the compromise.

Controls:
- dedicated logging account
- immutable/object-locked storage where required
- separate KMS administration
- no app-role delete path

### Queue replay / duplicate mutation
Risk: poisoned or retried queue messages cause duplicate billing/legal mutations.

Controls:
- idempotency key
- bounded receives
- DLQ
- visibility timeout
- replay tooling with explicit authorization

### Concurrency exhaustion
Risk: Lambda spikes consume RDS connections and create cascading failure.

Controls:
- reserved concurrency
- connection budget
- backpressure
- RDS Proxy where appropriate
- SLO-based alerting
