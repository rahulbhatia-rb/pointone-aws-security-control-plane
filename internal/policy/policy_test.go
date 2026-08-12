package policy

import "testing"

func safe() Contract {
	return Contract{
		Service: "billing-worker", Environment: "production",
		AccountIsolated: true, PermissionBoundary: true, IAMWildcardActions: nil,
		Trust: Trust{CrossAccount: true, ExternalIDRequired: true},
		PublicRDS: false, PublicAdminIngress: false,
		PrivateServiceConnectivity: true, RestrictedEgress: true,
		WorkloadIdentity: true, ManagedSecrets: true, KMSSeparated: true,
		ImmutableAuditLogs: true, LambdaReservedConcurrency: 50,
		RDSConnectionBudget: 120, IncidentOwner: "platform-security",
		Queue: Queue{DLQ: true, MaxReceiveCount: 5, VisibilityTimeout: 120, IdempotentWorker: true},
	}
}

func TestSafeContract(t *testing.T) {
	r := Evaluate(safe())
	if !r.Allowed {
		t.Fatalf("expected allowed: %+v", r.Findings)
	}
}

func TestWildcardIAMRejected(t *testing.T) {
	c := safe()
	c.IAMWildcardActions = []string{"iam:*"}
	if Evaluate(c).Allowed {
		t.Fatal("expected IAM wildcard rejection")
	}
}

func TestMutableLogsRejected(t *testing.T) {
	c := safe()
	c.ImmutableAuditLogs = false
	if Evaluate(c).Allowed {
		t.Fatal("expected immutable log rejection")
	}
}

func TestUnboundedLambdaRejected(t *testing.T) {
	c := safe()
	c.LambdaReservedConcurrency = 0
	if Evaluate(c).Allowed {
		t.Fatal("expected concurrency rejection")
	}
}
