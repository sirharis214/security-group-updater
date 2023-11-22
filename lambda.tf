locals {
  function_filename = "function" # .py is implied
}

# archive/zip the lambda folder to send to AWS Lambda
data "archive_file" "this" {
  type        = "zip"
  source_dir  = "${path.module}/functions/"
  output_path = "${path.module}/tmp/${local.function_filename}_package.zip"
}

# creating lambda and storing environmental variables
resource "aws_lambda_function" "this" {
  function_name    = "${local.module_name}-dev"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  role             = aws_iam_role.this.arn
  runtime          = "python3.9"
  handler          = "${local.function_filename}.lambda_handler"
  timeout          = 60  # Seconds
  memory_size      = 128 # MB

  depends_on = [aws_iam_role.this]
  tags       = local.tags
}
