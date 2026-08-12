package policy

type Trust struct {
	CrossAccount       bool `json:"cross_account"`
	ExternalIDRequired bool `json:"external_id_required"`
}

type Queue struct {
	DLQ               bool `json:"dlq"`
	MaxReceiveCount   int  `json:"max_receive_count"`
	VisibilityTimeout int  `json:"visibility_timeout_seconds"`
	IdempotentWorker  bool `json:"idempotent_worker"`
}

type Contract struct {
	Service                    string   `json:"service"`
	Environment                string   `json:"environment"`
	AccountIsolated            bool     `json:"account_isolated"`
	PermissionBoundary         bool     `json:"permission_boundary"`
	IAMWildcardActions         []string `json:"iam_wildcard_actions"`
	Trust                      Trust    `json:"trust"`
	PublicRDS                  bool     `json:"public_rds"`
	PublicAdminIngress         bool     `json:"public_admin_ingress"`
	PrivateServiceConnectivity bool     `json:"private_service_connectivity"`
	RestrictedEgress           bool     `json:"restricted_egress"`
	WorkloadIdentity           bool     `json:"workload_identity"`
	ManagedSecrets             bool     `json:"managed_secrets"`
	KMSSeparated               bool     `json:"kms_separated"`
	ImmutableAuditLogs         bool     `json:"immutable_audit_logs"`
	LambdaReservedConcurrency  int      `json:"lambda_reserved_concurrency"`
	RDSConnectionBudget        int      `json:"rds_connection_budget"`
	IncidentOwner              string   `json:"incident_owner"`
	Queue                      Queue    `json:"queue"`
}

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type Result struct {
	Allowed  bool      `json:"allowed"`
	Findings []Finding `json:"findings,omitempty"`
}

func Evaluate(c Contract) Result {
	var f []Finding

	if c.Environment == "production" {
		if !c.AccountIsolated {
			f = append(f, Finding{"high", "account_isolation_missing", "production workload must have an explicit account isolation boundary"})
		}
		if !c.PermissionBoundary {
			f = append(f, Finding{"high", "permission_boundary_missing", "sensitive delegated IAM requires a permission boundary"})
		}
		if len(c.IAMWildcardActions) > 0 {
			f = append(f, Finding{"critical", "iam_wildcard", "wildcard IAM actions are not allowed"})
		}
		if c.Trust.CrossAccount && !c.Trust.ExternalIDRequired {
			f = append(f, Finding{"high", "cross_account_trust_weak", "cross-account trust requires an explicit anti-confused-deputy control"})
		}
		if c.PublicRDS {
			f = append(f, Finding{"critical", "public_rds", "RDS must not be publicly exposed"})
		}
		if c.PublicAdminIngress {
			f = append(f, Finding{"critical", "public_admin_ingress", "administrative ingress must not be public"})
		}
		if !c.PrivateServiceConnectivity {
			f = append(f, Finding{"medium", "private_connectivity_missing", "prefer private service connectivity for sensitive internal paths"})
		}
		if !c.RestrictedEgress {
			f = append(f, Finding{"high", "egress_unrestricted", "production egress must be explicitly bounded"})
		}
		if !c.WorkloadIdentity {
			f = append(f, Finding{"critical", "static_credentials_risk", "workload identity is required"})
		}
		if !c.ManagedSecrets {
			f = append(f, Finding{"critical", "unmanaged_secrets", "managed secret storage is required"})
		}
		if !c.KMSSeparated {
			f = append(f, Finding{"high", "kms_segmentation_missing", "sensitive environments/data classes require KMS segmentation"})
		}
		if !c.ImmutableAuditLogs {
			f = append(f, Finding{"critical", "mutable_audit_logs", "audit logs must be immutable and independently protected"})
		}
		if c.LambdaReservedConcurrency <= 0 {
			f = append(f, Finding{"high", "lambda_concurrency_unbounded", "reserved concurrency required for sensitive Lambda paths"})
		}
		if c.RDSConnectionBudget <= 0 {
			f = append(f, Finding{"high", "rds_budget_missing", "RDS connection budget must be defined"})
		}
		if c.IncidentOwner == "" {
			f = append(f, Finding{"high", "incident_owner_missing", "incident ownership must be explicit"})
		}
		if !c.Queue.DLQ || c.Queue.MaxReceiveCount <= 0 || c.Queue.VisibilityTimeout <= 0 {
			f = append(f, Finding{"high", "queue_resilience_weak", "SQS retry, visibility timeout, and DLQ policy must be explicit"})
		}
		if !c.Queue.IdempotentWorker {
			f = append(f, Finding{"critical", "worker_not_idempotent", "mutation workers must be idempotent"})
		}
	}

	allowed := true
	for _, x := range f {
		if x.Severity == "high" || x.Severity == "critical" {
			allowed = false
		}
	}
	return Result{Allowed: allowed, Findings: f}
}
