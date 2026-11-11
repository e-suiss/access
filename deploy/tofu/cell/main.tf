# OP-51, T36, OP-158 m.3 (p): one Access cell's infrastructure: its namespace and the chart release.
# Realm and domain configuration is never here (tofu-infra-only).
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
  }
}

resource "kubernetes_namespace" "access" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "access"
      "access.suiss.dev/cell"     = var.cell
    }
  }
}

resource "helm_release" "access" {
  name      = "access"
  namespace = kubernetes_namespace.access.metadata[0].name
  chart     = "${path.module}/../../helm/access"
  values = [
    yamlencode({
      image = { sha256 = trimprefix(var.image_digest, "sha256:") }
      replicas   = var.replicas
      durability = var.durability
      cells = {
        this = var.cell
        list = [{ name = var.cell, region = var.region, class = var.class, url = var.url }]
      }
      planes = { split = var.plane_split }
    })
  ]
}
