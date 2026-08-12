# Blast Radius Strategy

Isolation should be proportional to consequence.

## Hard boundaries
Use separate AWS accounts when compromise must not naturally cross:
- production vs non-production
- logging/security administration
- high-sensitivity customer workloads
- shared platform vs security tooling

## Service boundaries
Inside an account:
- private subnets
- service-specific security groups
- workload identity
- per-service KMS grants where justified
- narrowly scoped secret access

## Failure containment
- Lambda reserved concurrency protects downstreams.
- SQS backpressure decouples bursts.
- RDS connection budgets prevent one workload from exhausting shared capacity.
- customer/data segmentation reduces legal and operational blast radius.

The goal is not maximum isolation everywhere; it is intentional, reviewable isolation at the boundaries that matter.
