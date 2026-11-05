# Clean fixture: this folder must produce no finding.

variable "tenant_id" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "azurerm_resource_group" "ledger" {
  name     = "ledger-prod"
  location = "westeurope"
}

resource "azurerm_storage_account" "statements" {
  name                     = "ledgerstatements"
  resource_group_name      = azurerm_resource_group.ledger.name
  location                 = azurerm_resource_group.ledger.location
  account_tier             = "Standard"
  account_replication_type = "GZRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_container" "statements" {
  name                  = "statements"
  storage_account_name  = azurerm_storage_account.statements.name
  container_access_type = "private"
}

resource "azurerm_postgresql_flexible_server" "ledger" {
  name                   = "ledger-db"
  resource_group_name    = azurerm_resource_group.ledger.name
  location               = azurerm_resource_group.ledger.location
  version                = "16"
  sku_name               = "GP_Standard_D2s_v3"
  storage_mb             = 131072
  administrator_login    = "ledger"
  administrator_password = var.db_password

  high_availability {
    mode = "ZoneRedundant"
  }
}

resource "azurerm_key_vault" "ledger" {
  name                     = "ledger-vault"
  resource_group_name      = azurerm_resource_group.ledger.name
  location                 = azurerm_resource_group.ledger.location
  tenant_id                = var.tenant_id
  sku_name                 = "standard"
  purge_protection_enabled = true
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
    name                       = "ssh-from-bastion-subnet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.30.5.0/24"
    destination_address_prefix = "*"
  }
}

resource "azurerm_linux_virtual_machine_scale_set" "workers" {
  name                = "ledger-workers"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  sku                 = "Standard_D2s_v5"
  instances           = 3
  admin_username      = "ledgeradmin"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
}

resource "azurerm_log_analytics_workspace" "ledger" {
  name                = "ledger-logs"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
}
