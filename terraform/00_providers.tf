# remote state backend and providers initialization
terraform {
  # terraform cloud backend
  backend "remote" {
    organization = "knoxknot"
    workspaces {
      name = "knoxknot-github-io"
    }  
  }

  # namecheap provider
  required_providers {
    namecheap = {
      source = "namecheap/namecheap"
      version = ">= 2.0.0"
    }
  }
}

# provider settings
provider "namecheap" {
  user_name = var.namecheap_username
  api_user = var.namecheap_username
  api_key = var.namecheap_api_key
}