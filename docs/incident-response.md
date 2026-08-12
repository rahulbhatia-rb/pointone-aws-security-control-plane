# Incident Response Playbooks

## Leaked AWS credential

1. Identify principal and active sessions.
2. Disable/rotate credential.
3. Revoke active sessions where supported.
4. Inspect CloudTrail for AssumeRole, policy, key, network, and data-access activity.
5. Preserve relevant logs and snapshots.
6. Contain affected account/workload.
7. Rotate downstream secrets reachable by the principal.
8. Restore service with a reduced privilege set.
9. Add a preventive control to the security gate.

## Compromised workload role

1. Block the role/session path.
2. Isolate workload/network.
3. Inspect role trust and lateral AssumeRole attempts.
4. Review KMS/Secrets Manager/S3/RDS access.
5. Redeploy from known-good artifact.
6. Remove escalation paths.
7. Exercise the same attack path in staging.

## Suspicious infrastructure change

1. Identify IaC or console origin.
2. Freeze further deploys to affected environment.
3. Compare intended IaC state to actual state.
4. Preserve CloudTrail/Config evidence.
5. Roll back unsafe exposure.
6. Add policy-as-code control preventing recurrence.
