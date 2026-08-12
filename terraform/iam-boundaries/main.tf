data "aws_iam_policy_document" "boundary" {
  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "permission_boundary" {
  name   = "pointone-sensitive-workload-boundary"
  policy = data.aws_iam_policy_document.boundary.json
}
