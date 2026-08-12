variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }

# Reference intent:
# - sensitive services remain in private subnets
# - use VPC endpoints / PrivateLink where appropriate
# - no public RDS
# - SG rules are service-to-service, not broad CIDR access
# - outbound access is explicitly allowlisted where feasible

resource "aws_security_group" "service" {
  name   = "pointone-sensitive-service"
  vpc_id = var.vpc_id

  egress {
    description = "HTTPS only; production should narrow destinations further"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
