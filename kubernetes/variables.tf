variable "primary_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  description = "enviroment for deployment"
  type        = string
  default     = "_dev"
}

variable "public_subnets" {
  default = {
    "public_subnet_1" = 1
    "public_subnet_2" = 2
  }
}
variable "private_subnets" {
  default = {
    "private_subnet_1" = 1
    "private_subnet_2" = 2
  }
}
variable "vpc_cidr" {
  type    = string
  default = "119.0.0.0/16"
}

variable "allow_all_cidr" {
  type    = string
  default = "0.0.0.0/0"
}
variable "rule_action_allow" {
  type    = string
  default = "allow"
}

variable "keypair_name" {
  default = "bastionKP"
}

variable "local_private_key" {
  default = "bastionKP.pem"
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}