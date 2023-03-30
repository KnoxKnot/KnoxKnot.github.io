# dns settings
resource "namecheap_domain_records" "samuelnwoye_a" {
  domain = "samuelnwoye.website"
  mode = "OVERWRITE"

  dynamic "record" {
    for_each = var.a_records
    iterator = "address"
    content {
      address = address.value
      hostname = "@"
      ttl = 60
      type = "A"
    }
  }
}

resource "namecheap_domain_records" "samuelnwoye_cname" {
  domain = "samuelnwoye.website"
  mode = "OVERWRITE"

  record {
    address = "knoxknot.github.io."
    hostname = "www"
    ttl = 60
    type = "CNAME"
  }
}

resource "namecheap_domain_records" "samuelnwoye_ns" {
  domain = "samuelnwoye.website"
  mode = "OVERWRITE"

  nameservers = [
    "dns1.registrar-servers.com",
    "dns2.registrar-servers.com"
  ] 
}