locals {
  module_tags = {
    module_name = join("/", compact([
      lookup(var.project_tags, "module_name", null),
      local.module_name
    ]))
    module_repo = "https://github.com/sirharis214/aws-haris-sandbox"
  }
  tags = merge(var.project_tags, local.module_tags)
}
