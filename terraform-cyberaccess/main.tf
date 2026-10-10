locals {
  creating_tenant = var.tenant_name != ""
  generated_dir   = "${path.module}/.generated"
  windows_host    = can(regex("^[A-Za-z]:", abspath(path.root)))
  curl_command    = local.windows_host ? "curl.exe" : "curl"
  command_interpreter = local.windows_host ? [
    "PowerShell", "-NoProfile", "-NonInteractive", "-Command"
  ] : ["/bin/sh", "-c"]

  alert_channel_map = {
    for idx, ch in var.alert_channels :
    "${idx}-${substr(md5(jsonencode(ch)), 0, 8)}" => ch
  }
}

# ---- Tenant creation (POST /v1/tenants is not idempotent - it mints a new
# random tenant_id + api_key on every call - so this only ever runs once,
# guarded by triggers on the inputs that would otherwise cause a silent
# re-create). Skipped entirely when existing_tenant_id is set instead. ----

resource "local_file" "tenant_create_payload" {
  count    = local.creating_tenant ? 1 : 0
  filename = "${local.generated_dir}/tenant_create_payload.json"
  content  = jsonencode({ name = var.tenant_name })
}

resource "local_sensitive_file" "signup_headers" {
  count           = local.creating_tenant ? 1 : 0
  filename        = "${local.generated_dir}/signup_headers.txt"
  content         = "X-Signup-Key: ${var.signup_key}\n"
  file_permission = "0600"
}

resource "null_resource" "create_tenant" {
  count = local.creating_tenant ? 1 : 0

  triggers = {
    tenant_name = var.tenant_name
    base_url    = var.base_url
  }

  provisioner "local-exec" {
    interpreter = local.command_interpreter
    command     = "${local.curl_command} -fsS --connect-timeout 5 --max-time 30 -X POST \"${var.base_url}/v1/tenants\" -H \"Content-Type: application/json\" -H \"@${local_sensitive_file.signup_headers[0].filename}\" -d \"@${local_file.tenant_create_payload[0].filename}\" -o \"${local.generated_dir}/tenant_create_response.json\""
  }

  depends_on = [local_file.tenant_create_payload]
}

# Re-reads the persisted response on every plan/apply so tenant_id/api_key
# stay available as outputs even once create_tenant itself stops re-running.
data "local_file" "tenant_create_response" {
  count      = local.creating_tenant ? 1 : 0
  filename   = "${local.generated_dir}/tenant_create_response.json"
  depends_on = [null_resource.create_tenant]
}

locals {
  created_tenant = local.creating_tenant ? jsondecode(data.local_file.tenant_create_response[0].content) : null
  tenant_id      = local.creating_tenant ? local.created_tenant.tenant_id : var.existing_tenant_id
  api_key        = local.creating_tenant ? local.created_tenant.api_key : var.tenant_api_key
  auth_header    = local.api_key != "" ? "X-API-Key: ${local.api_key}" : "Authorization: Bearer ${var.admin_jwt}"
}

resource "local_sensitive_file" "tenant_headers" {
  filename        = "${local.generated_dir}/tenant_headers.txt"
  content         = "${local.auth_header}\n"
  file_permission = "0600"
}

# ---- Quota (POST /tenants/{id}/quota IS a genuine upsert - safe to re-apply
# on every run; the trigger hash just avoids an unnecessary API call when
# nothing changed). ----

resource "local_file" "quota_payload" {
  filename = "${local.generated_dir}/quota_payload.json"
  content = jsonencode({
    requests_per_minute      = try(var.quota.requests_per_minute, null)
    max_stored_audit_events  = try(var.quota.max_stored_audit_events, null)
    max_audit_retention_days = try(var.quota.max_audit_retention_days, null)
    risk_threshold_block     = try(var.quota.risk_threshold_block, null)
    risk_threshold_warn      = try(var.quota.risk_threshold_warn, null)
  })
}

resource "null_resource" "set_quota" {
  triggers = {
    tenant_id  = local.tenant_id
    quota_hash = md5(local_file.quota_payload.content)
  }

  provisioner "local-exec" {
    interpreter = local.command_interpreter
    command     = "${local.curl_command} -fsS --connect-timeout 5 --max-time 30 -X POST \"${var.base_url}/tenants/${local.tenant_id}/quota\" -H \"Content-Type: application/json\" -H \"@${local_sensitive_file.tenant_headers.filename}\" -d \"@${local_file.quota_payload.filename}\""
  }

  depends_on = [local_file.quota_payload, null_resource.create_tenant]
}

# ---- Alert channels (POST /tenants/{id}/alert-channels mints a new random
# channel_id per call too - see variables.tf's alert_channels doc for the
# create-once-per-config, no-in-place-update caveat this implies). ----

resource "local_file" "alert_channel_payload" {
  for_each = local.alert_channel_map
  filename = "${local.generated_dir}/alert_channel_${each.key}.json"
  content = jsonencode({
    channel_type   = each.value.channel_type
    channel_config = each.value.channel_config
  })
}

resource "null_resource" "create_alert_channel" {
  for_each = local.alert_channel_map

  triggers = {
    tenant_id = local.tenant_id
    config    = jsonencode(each.value)
  }

  provisioner "local-exec" {
    interpreter = local.command_interpreter
    command     = "${local.curl_command} -fsS --connect-timeout 5 --max-time 30 -X POST \"${var.base_url}/tenants/${local.tenant_id}/alert-channels\" -H \"Content-Type: application/json\" -H \"@${local_sensitive_file.tenant_headers.filename}\" -d \"@${local_file.alert_channel_payload[each.key].filename}\""
  }

  depends_on = [local_file.alert_channel_payload, null_resource.create_tenant]
}
