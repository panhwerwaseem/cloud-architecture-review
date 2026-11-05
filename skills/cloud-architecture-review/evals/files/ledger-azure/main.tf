# Ledger service on Azure. Eval fixture: the weaknesses are planted.
# Every password-like value in this folder is a made-up placeholder.

provider "azurerm" {
  features {}
}

variable "tenant_id" {
  type = string
}

variable "archive_replication" {
  type    = string
  default = "LRS"
}

resource "azurerm_resource_group" "ledger" {
  name     = "ledger-prod"
  location = "westeurope"
}

resource "azurerm_storage_account" "statements" {
  name                       = "ledgerstatements"
  resource_group_name        = azurerm_resource_group.ledger.name
  location                   = azurerm_resource_group.ledger.location
  account_tier               = "Standard"
  account_replication_type   = "LRS"
  https_traffic_only_enabled = false
  min_tls_version            = "TLS1_0"
}

resource "azurerm_storage_container" "statements" {
  name                  = "statements"
  storage_account_name  = azurerm_storage_account.statements.name
  container_access_type = "blob"
}

resource "azurerm_storage_account" "archive" {
  name                     = "ledgerarchive"
  resource_group_name      = azurerm_resource_group.ledger.name
  location                 = azurerm_resource_group.ledger.location
  account_tier             = "Standard"
  account_replication_type = var.archive_replication
}

resource "azurerm_postgresql_flexible_server" "ledger" {
  name                   = "ledger-db"
  resource_group_name    = azurerm_resource_group.ledger.name
  location               = azurerm_resource_group.ledger.location
  version                = "16"
  sku_name               = "GP_Standard_D2s_v3"
  storage_mb             = 131072
  administrator_login    = "ledger"
  administrator_password = "example-only-not-a-real-password"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "anywhere" {
  name             = "anywhere"
  server_id        = azurerm_postgresql_flexible_server.ledger.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "azure-services"
  server_id        = azurerm_postgresql_flexible_server.ledger.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_key_vault" "ledger" {
  name                = "ledger-vault"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  tenant_id           = var.tenant_id
  sku_name            = "standard"
}

resource "azurerm_key_vault_secret" "signing" {
  name         = "signing-key"
  value        = "example-only-signing-key"
  key_vault_id = azurerm_key_vault.ledger.id
}

resource "azurerm_network_security_group" "app" {
  name                = "ledger-app"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location

  security_rule {
    name                       = "https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "ssh" {
  name                        = "ssh"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.ledger.name
  network_security_group_name = azurerm_network_security_group.app.name
}

resource "azurerm_linux_virtual_machine" "app" {
  name                            = "ledger-app"
  resource_group_name             = azurerm_resource_group.ledger.name
  location                        = azurerm_resource_group.ledger.location
  size                            = "Standard_D2s_v5"
  admin_username                  = "ledgeradmin"
  admin_password                  = "example-only-vm-password"
  disable_password_authentication = false
  network_interface_ids           = [var.app_nic_id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
}

variable "app_nic_id" {
  type = string
}

resource "azurerm_linux_virtual_machine_scale_set" "workers" {
  name                = "ledger-workers"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  sku                 = "Standard_D2s_v5"
  instances           = 1
  admin_username      = "ledgeradmin"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
}
