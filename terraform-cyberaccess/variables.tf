variable "base_url" {
  description = "Base URL of your CyberAccess backend, e.g. https://cyberaccess.your-company.com"
  type        = string
}

variable "signup_key" {
  description = "TENANT_SIGNUP_KEY configured on the CyberAccess backend. Required only when creating a new tenant (var.tenant_name set, var.existing_tenant_id unset)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "admin_jwt" {
  description = "Optional admin JWT scoped to the managed tenant. Newly created tenants automatically use their generated API key instead."
  type        = string
  sensitive   = true
  default     = ""
}

variable "tenant_api_key" {
  description = "API key for existing_tenant_id, used to manage that tenant's quota and alert channels."
  type        = string
  sensitive   = true
  default     = ""
}

variable "tenant_name" {
  description = "Display name for a new tenant. Set this (and leave existing_tenant_id empty) to provision a brand new tenant."
  type        = string
  default     = ""
}

variable "existing_tenant_id" {
  description = "An existing tenant_id to manage quota/alert-channels for, instead of creating a new one. Set this OR tenant_name, not both."
  type        = string
  default     = ""
}

variable "quota" {
  description = "Per-tenant quota configuration. Any field left null keeps the backend's current value for that field (the API upserts with COALESCE, so partial updates are safe)."
  type = object({
    requests_per_minute      = optional(number)
    max_stored_audit_events  = optional(number)
    max_audit_retention_days = optional(number)
    risk_threshold_block     = optional(number)
    risk_threshold_warn      = optional(number)
  })
  default = {}
}

variable "alert_channels" {
  description = <<-EOT
    Alert channels to provision for this tenant. Each entry creates ONE channel -
    the backend's /alert-channels endpoint assigns a new random channel_id per
    call, so it is NOT upsert-by-name: re-running apply with the same list after
    a successful first apply will not create duplicates (guarded by triggers
    keyed on the channel's own config), but changing an existing entry's config
    creates a new channel rather than updating the old one in place. Delete the
    stale channel manually via the API if you rotate a channel's config.
  EOT
  type = list(object({
    channel_type   = string # "slack" | "email" | "webhook"
    channel_config = map(string)
  }))
  default = []
}
