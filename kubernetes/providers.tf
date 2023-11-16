terraform {
  backend "s3" {
    bucket = "terraform-state-file-mf37" // tf state will be stored here
    key    = "kubernetes/infra"
    //region = var.primary_region
  }

  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.18.1" 
      
    }
  } 
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region
}









/*
Switch backend to terraform cloud

backend "remote" {
    hostname     = "app.terraform.io"
    organization = "default-mf"
    workspaces {
      name = "Cloudfront"
    }
  }
  

Swtich to s3 backend

backend "s3" {
    bucket = "terraform-state-file-mf37" // tf state will be stored here
    key    = "kubernetes/infra"
    region = "us-east-1"
  }

Switch to local

backend "local" {
    path = "terraform.tfstate"
  }

*/