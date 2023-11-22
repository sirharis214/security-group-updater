# IAM policy document that grants permission for AWS Lambda to assume roles
data "aws_iam_policy_document" "this" {
  statement {
    sid     = "AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole", ]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", ]
    }
  }
}

# The IAM Role
resource "aws_iam_role" "this" {
  name_prefix        = "${local.module_name}-"
  assume_role_policy = data.aws_iam_policy_document.this.json
  tags               = local.tags
}

# Grant lambda iam-role permissions to other resources such as CloudWatch and DynamoDB
data "aws_iam_policy_document" "permissions" {
  statement {
    sid    = "CWLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.this.arn}:*",
      "${aws_cloudwatch_log_group.this.arn}:*:*",
    ]
  }

  statement {
    sid    = "SgUpdater"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroupRules",
      "ec2:ModifySecurityGroupRules",
      "ec2:DescribeSecurityGroups",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateTags",
    ]
    resources = [
      "*",
    ]
  }
}

# Attaching Lambda permissons to iam-role
resource "aws_iam_role_policy" "this" {
  name_prefix = "${local.module_name}-BasicExecution-"
  role        = aws_iam_role.this.name
  policy      = data.aws_iam_policy_document.permissions.json
}
