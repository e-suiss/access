# OP-51, OP-158 m.3 (o), (p): what differs between cells.
variable "cell" {
  description = "The cell's name, ^[a-z0-9][a-z0-9-]{0,62}$."
  type        = string
}

variable "region" {
  description = "The region the cell's data stays in."
  type        = string
}

variable "class" {
  description = "regional or multi-region-sync."
  type        = string
  default     = "regional"
}

variable "url" {
  description = "The cell's public URL, which a misdirected request is pointed to."
  type        = string
}

variable "namespace" {
  type    = string
  default = "access"
}

variable "image_digest" {
  description = "The access image digest, sha256:..."
  type        = string
}

variable "replicas" {
  type    = number
  default = 3
}

variable "durability" {
  description = "replicated, or single-node for the small-provider profile."
  type        = string
  default     = "replicated"
}

variable "plane_split" {
  description = "Whether the two planes' signers read separate secret stores."
  type        = bool
  default     = false
}
