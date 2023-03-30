variable "a_records" {
  default = [ "185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153" ]
  description = "Github Server IPs for A Records"
  type = list(string)
}

variable "namecheap_api_key" {
  description = "Namecheap API Key"
  sensitive = true
  type = string
}

variable "namecheap_username" {
  description = "Namecheap Username"
  default = "knoxknot"
  type = string
}