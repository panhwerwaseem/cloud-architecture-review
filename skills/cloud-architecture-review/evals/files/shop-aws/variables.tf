variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "ami" {
  type = string
}

variable "reporting_instance_class" {
  type    = string
  default = "db.m6g.large"
}

variable "reporting_multi_az" {
  type    = bool
  default = false
}

variable "reporting_password" {
  type      = string
  sensitive = true
}

variable "backup_days" {
  type = number
}

variable "internal_ports" {
  type    = list(number)
  default = [8080, 9090]
}

variable "internal_cidrs" {
  type = list(string)
}
