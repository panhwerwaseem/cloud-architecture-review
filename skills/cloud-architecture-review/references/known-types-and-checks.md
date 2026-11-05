# Known resource types and checks

What `scripts/iac_inventory.py` recognises and what `scripts/iac_checks.py`
tests. Anything not listed here is not checked. The scripts print the same
lists: `iac_inventory.py --list-types` and `iac_checks.py`.

Attribute names and defaults were written against the `hashicorp/aws`,
`hashicorp/azurerm` and `hashicorp/google` provider documentation and the
CloudFormation resource reference. Providers rename attributes and change
defaults between major versions. Before reporting a finding that rests on a
default ("is not set (documented default: ...)"), check the documentation for
the provider version the repository pins.

## Contents

- [How a value is read](#how-a-value-is-read)
- [Known resource types](#known-resource-types)
- [Checks on one attribute](#checks-on-one-attribute)
- [Checks on firewall rules](#checks-on-firewall-rules)
- [Other checks](#other-checks)
- [Secrets written as literal values](#secrets-written-as-literal-values)
- [What is not checked](#what-is-not-checked)

## How a value is read

| In the code | What the script does |
|---|---|
| A literal (`true`, `0`, `"ZONAL"`, a list or map of literals) | Tests it |
| Not set, and the documented default is the weak setting | Reports a finding that says "is not set (documented default: ...)" |
| Not set, and the default is safe | Nothing |
| Not set, and the script does not state a default | Reports "not evaluated" |
| An expression: `var.x`, `local.x`, a function call, a conditional, a string with `${...}`, a CloudFormation intrinsic such as `Ref` | Reports "not evaluated" with the expression |
| Inside a `dynamic` block | Reports "not evaluated" |
| Inside a `module` | Not read. Each module call is listed once as "not evaluated" |

Variable defaults and `.tfvars` values are never substituted, because the
script cannot know which environment is being applied.

## Known resource types

Terraform types are lower case. CloudFormation types start with `AWS::`.
Resources of any other type are counted under "uncategorised" and not checked.

| Cloud | Category | Types |
|---|---|---|
| aws | compute | `aws_instance`, `aws_launch_template`, `aws_autoscaling_group`, `aws_ecs_cluster`, `aws_ecs_service`, `aws_ecs_task_definition`, `aws_eks_cluster`, `aws_eks_node_group`, `aws_lambda_function`, `AWS::EC2::Instance`, `AWS::EC2::LaunchTemplate`, `AWS::AutoScaling::AutoScalingGroup`, `AWS::ECS::Cluster`, `AWS::ECS::Service`, `AWS::ECS::TaskDefinition`, `AWS::EKS::Cluster`, `AWS::EKS::Nodegroup`, `AWS::Lambda::Function`, `AWS::Serverless::Function` |
| aws | data | `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance`, `aws_dynamodb_table`, `aws_s3_bucket`, `aws_s3_bucket_acl`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_policy`, `aws_ebs_volume`, `aws_ebs_encryption_by_default`, `aws_efs_file_system`, `aws_elasticache_cluster`, `aws_elasticache_replication_group`, `aws_redshift_cluster`, `aws_opensearch_domain`, `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::DynamoDB::Table`, `AWS::S3::Bucket`, `AWS::S3::BucketPolicy`, `AWS::EC2::Volume`, `AWS::EFS::FileSystem`, `AWS::ElastiCache::CacheCluster`, `AWS::ElastiCache::ReplicationGroup`, `AWS::Redshift::Cluster`, `AWS::OpenSearchService::Domain` |
| aws | network | `aws_vpc`, `aws_subnet`, `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`, `aws_internet_gateway`, `aws_nat_gateway`, `aws_route_table`, `aws_eip`, `aws_lb`, `aws_alb`, `aws_elb`, `aws_lb_listener`, `aws_lb_target_group`, `aws_cloudfront_distribution`, `aws_route53_zone`, `aws_route53_record`, `aws_api_gateway_rest_api`, `aws_apigatewayv2_api`, `AWS::EC2::VPC`, `AWS::EC2::Subnet`, `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`, `AWS::EC2::InternetGateway`, `AWS::EC2::NatGateway`, `AWS::EC2::RouteTable`, `AWS::EC2::EIP`, `AWS::ElasticLoadBalancingV2::LoadBalancer`, `AWS::ElasticLoadBalancingV2::Listener`, `AWS::ElasticLoadBalancingV2::TargetGroup`, `AWS::ElasticLoadBalancing::LoadBalancer`, `AWS::CloudFront::Distribution`, `AWS::Route53::HostedZone`, `AWS::Route53::RecordSet`, `AWS::ApiGateway::RestApi`, `AWS::ApiGatewayV2::Api` |
| aws | identity | `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_user`, `aws_iam_access_key`, `aws_iam_instance_profile`, `aws_kms_key`, `aws_secretsmanager_secret`, `aws_secretsmanager_secret_version`, `aws_ssm_parameter`, `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::User`, `AWS::IAM::AccessKey`, `AWS::IAM::InstanceProfile`, `AWS::KMS::Key`, `AWS::SecretsManager::Secret`, `AWS::SSM::Parameter` |
| aws | observability | `aws_cloudwatch_metric_alarm`, `aws_cloudwatch_log_group`, `aws_cloudwatch_dashboard`, `aws_cloudtrail`, `aws_flow_log`, `AWS::CloudWatch::Alarm`, `AWS::Logs::LogGroup`, `AWS::CloudWatch::Dashboard`, `AWS::CloudTrail::Trail`, `AWS::EC2::FlowLog` |
| azure | compute | `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`, `azurerm_linux_virtual_machine_scale_set`, `azurerm_windows_virtual_machine_scale_set`, `azurerm_kubernetes_cluster`, `azurerm_kubernetes_cluster_node_pool`, `azurerm_service_plan`, `azurerm_linux_web_app`, `azurerm_windows_web_app`, `azurerm_linux_function_app`, `azurerm_windows_function_app`, `azurerm_container_app`, `azurerm_container_group` |
| azure | data | `azurerm_storage_account`, `azurerm_storage_container`, `azurerm_managed_disk`, `azurerm_mssql_server`, `azurerm_mssql_database`, `azurerm_mssql_firewall_rule`, `azurerm_postgresql_flexible_server`, `azurerm_postgresql_flexible_server_firewall_rule`, `azurerm_mysql_flexible_server`, `azurerm_mysql_flexible_server_firewall_rule`, `azurerm_cosmosdb_account`, `azurerm_redis_cache` |
| azure | network | `azurerm_virtual_network`, `azurerm_subnet`, `azurerm_network_security_group`, `azurerm_network_security_rule`, `azurerm_public_ip`, `azurerm_lb`, `azurerm_application_gateway`, `azurerm_nat_gateway`, `azurerm_network_interface`, `azurerm_dns_zone`, `azurerm_private_endpoint`, `azurerm_firewall`, `azurerm_cdn_frontdoor_profile` |
| azure | identity | `azurerm_role_assignment`, `azurerm_role_definition`, `azurerm_user_assigned_identity`, `azurerm_key_vault`, `azurerm_key_vault_secret`, `azurerm_key_vault_key`, `azurerm_key_vault_access_policy` |
| azure | observability | `azurerm_log_analytics_workspace`, `azurerm_application_insights`, `azurerm_monitor_metric_alert`, `azurerm_monitor_action_group`, `azurerm_monitor_diagnostic_setting`, `azurerm_monitor_activity_log_alert` |
| gcp | compute | `google_compute_instance`, `google_compute_instance_template`, `google_compute_instance_group_manager`, `google_compute_region_instance_group_manager`, `google_compute_autoscaler`, `google_compute_region_autoscaler`, `google_container_cluster`, `google_container_node_pool`, `google_cloud_run_service`, `google_cloud_run_v2_service`, `google_cloudfunctions_function`, `google_cloudfunctions2_function` |
| gcp | data | `google_sql_database_instance`, `google_sql_database`, `google_sql_user`, `google_storage_bucket`, `google_storage_bucket_iam_member`, `google_storage_bucket_iam_binding`, `google_compute_disk`, `google_redis_instance`, `google_bigquery_dataset`, `google_bigquery_table`, `google_spanner_instance`, `google_bigtable_instance`, `google_firestore_database`, `google_filestore_instance` |
| gcp | network | `google_compute_network`, `google_compute_subnetwork`, `google_compute_firewall`, `google_compute_router`, `google_compute_router_nat`, `google_compute_address`, `google_compute_global_address`, `google_compute_forwarding_rule`, `google_compute_global_forwarding_rule`, `google_compute_backend_service`, `google_compute_url_map`, `google_compute_target_https_proxy`, `google_dns_managed_zone`, `google_dns_record_set` |
| gcp | identity | `google_service_account`, `google_service_account_key`, `google_project_iam_member`, `google_project_iam_binding`, `google_kms_key_ring`, `google_kms_crypto_key`, `google_secret_manager_secret`, `google_secret_manager_secret_version` |
| gcp | observability | `google_monitoring_alert_policy`, `google_monitoring_notification_channel`, `google_monitoring_uptime_check_config`, `google_monitoring_dashboard`, `google_logging_metric`, `google_logging_project_sink` |
| kubernetes | compute | `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, `HorizontalPodAutoscaler`, `PodDisruptionBudget` |
| kubernetes | data | `PersistentVolumeClaim`, `PersistentVolume` |
| kubernetes | network | `Service`, `Ingress`, `NetworkPolicy` |
| kubernetes | identity | `ServiceAccount`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, `Secret` |
| kubernetes | observability | `ServiceMonitor`, `PodMonitor`, `PrometheusRule` |
| compose | compute | `service` |

## Checks on one attribute

"Unset" says what happens when the attribute is absent: **finding** (the
documented default is weak), **nothing** (the default is safe or the attribute
is required), or **not evaluated**.

| Check | Severity | Resource type | Attribute | Finding when | Unset |
|---|---|---|---|---|---|
| `db-single-zone` | medium | `aws_db_instance` | `multi_az` | false | finding |
| `db-single-zone` | medium | `AWS::RDS::DBInstance` | `MultiAZ` | false | finding |
| `db-single-zone` | medium | `google_sql_database_instance` | `settings.availability_type` | `ZONAL` | finding |
| `db-single-zone` | medium | `google_redis_instance` | `tier` | `BASIC` | finding |
| `db-backups-disabled` | high | `aws_db_instance` | `backup_retention_period` | 0 | not evaluated |
| `db-backups-disabled` | high | `AWS::RDS::DBInstance` | `BackupRetentionPeriod` | 0 | nothing |
| `db-backups-disabled` | high | `google_sql_database_instance` | `settings.backup_configuration.enabled` | false | not evaluated |
| `db-no-point-in-time-recovery` | medium | `aws_dynamodb_table` | `point_in_time_recovery.enabled` | false | finding |
| `db-no-point-in-time-recovery` | medium | `AWS::DynamoDB::Table` | `PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled` | false | finding |
| `no-deletion-protection` | medium | `aws_db_instance`, `aws_rds_cluster` | `deletion_protection` | false | finding |
| `no-deletion-protection` | medium | `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster` | `DeletionProtection` | false | finding |
| `no-deletion-protection` | medium | `aws_dynamodb_table` | `deletion_protection_enabled` | false | finding |
| `no-deletion-protection` | medium | `AWS::DynamoDB::Table` | `DeletionProtectionEnabled` | false | finding |
| `no-deletion-protection` | medium | `azurerm_key_vault` | `purge_protection_enabled` | false | finding |
| `no-deletion-protection` | medium | `google_sql_database_instance` | `deletion_protection` | false | nothing |
| `storage-not-encrypted` | high | `aws_db_instance` | `storage_encrypted` | false | finding |
| `storage-not-encrypted` | high | `AWS::RDS::DBInstance` | `StorageEncrypted` | false | finding |
| `storage-not-encrypted` | high | `aws_rds_cluster` | `storage_encrypted` | false | finding, unless `engine_mode` is `serverless` |
| `storage-not-encrypted` | high | `AWS::RDS::DBCluster` | `StorageEncrypted` | false | finding, unless `EngineMode` is `serverless` |
| `storage-not-encrypted` | medium | `aws_ebs_volume` | `encrypted` | false | finding, unless an `aws_ebs_encryption_by_default` resource is in the scan |
| `storage-not-encrypted` | medium | `AWS::EC2::Volume` | `Encrypted` | false | finding |
| `storage-not-encrypted` | medium | `aws_efs_file_system` | `encrypted` | false | finding |
| `storage-not-encrypted` | medium | `AWS::EFS::FileSystem` | `Encrypted` | false | finding |
| `public-database` | high | `aws_db_instance` | `publicly_accessible` | true | nothing |
| `public-database` | high | `AWS::RDS::DBInstance`, `AWS::Redshift::Cluster` | `PubliclyAccessible` | true | nothing |
| `public-database` | high | `aws_redshift_cluster` | `publicly_accessible` | true | not evaluated |
| `public-storage` | high | `aws_s3_bucket`, `aws_s3_bucket_acl` | `acl` | `public-read`, `public-read-write` | nothing |
| `public-storage` | high | `AWS::S3::Bucket` | `AccessControl` | `PublicRead`, `PublicReadWrite` | nothing |
| `public-storage` | high | `azurerm_storage_container` | `container_access_type` | `blob`, `container` | nothing |
| `insecure-transport` | medium | `azurerm_storage_account` | `https_traffic_only_enabled`, or `enable_https_traffic_only` in older provider versions | false | nothing |
| `insecure-transport` | medium | `azurerm_storage_account` | `min_tls_version` | `TLS1_0`, `TLS1_1` | nothing |
| `storage-not-zone-redundant` | low | `azurerm_storage_account` | `account_replication_type` | `LRS` | nothing |
| `single-instance` | low | `aws_autoscaling_group` | `max_size` | 1 | nothing |
| `single-instance` | low | `AWS::AutoScaling::AutoScalingGroup` | `MaxSize` | 1 | nothing |
| `single-instance` | low | `aws_ecs_service` | `desired_count` | 1 | nothing |
| `single-instance` | low | `AWS::ECS::Service` | `DesiredCount` | 1 | nothing |
| `single-instance` | low | `azurerm_linux_virtual_machine_scale_set`, `azurerm_windows_virtual_machine_scale_set` | `instances` | 1 | nothing |
| `single-instance` | low | `google_compute_instance_group_manager`, `google_compute_region_instance_group_manager` | `target_size` | 1 | nothing |
| `log-retention-unbounded` | low | `aws_cloudwatch_log_group` | `retention_in_days` | 0 | finding |
| `log-retention-unbounded` | low | `AWS::Logs::LogGroup` | `RetentionInDays` | (absent) | finding |

CloudFormation attributes are under `Properties`. In CloudFormation, the
strings `"true"`, `"false"` and numeric strings are read as booleans and
numbers.

Replicas and restores are skipped with a "not evaluated" note, because the
setting comes from the source: an `aws_db_instance` with `replicate_source_db`
(and, for encryption, `snapshot_identifier`); an `aws_rds_cluster` with
`snapshot_identifier` or `replication_source_identifier`; an
`AWS::RDS::DBInstance` with `DBClusterIdentifier`,
`SourceDBInstanceIdentifier` or (for encryption) `DBSnapshotIdentifier`; a
`google_sql_database_instance` with `master_instance_name`.

Not checked on purpose: encryption at rest for `aws_s3_bucket`,
`aws_dynamodb_table`, `azurerm_storage_account`, `azurerm_managed_disk`,
`google_storage_bucket`, `google_compute_disk` and
`google_sql_database_instance`. Those services encrypt stored data by default
and the code cannot turn it off. Whether a customer-managed key is required
is a question for the user.

## Checks on firewall rules

`open-ingress` reads inbound rules whose source is `0.0.0.0/0`, `::/0`, `*`
or the Azure service tag `Internet`.

| Rule allows | Result |
|---|---|
| Every port, or a range that includes 22, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 11211 or 27017 | high |
| Only 80 and 443 | no finding |
| Any other port | medium |
| ICMP or another protocol without ports | no finding |
| A source or port that is an expression | not evaluated |

| Resource type | Attributes read |
|---|---|
| `aws_security_group` (inline `ingress` blocks), `aws_security_group_rule` with `type = "ingress"` | `cidr_blocks`, `ipv6_cidr_blocks`, `from_port`, `to_port`, `protocol` |
| `aws_vpc_security_group_ingress_rule` | `cidr_ipv4`, `cidr_ipv6`, `from_port`, `to_port`, `ip_protocol` |
| `AWS::EC2::SecurityGroup` (`SecurityGroupIngress` list), `AWS::EC2::SecurityGroupIngress` | `CidrIp`, `CidrIpv6`, `FromPort`, `ToPort`, `IpProtocol` |
| `azurerm_network_security_group` (inline `security_rule` blocks), `azurerm_network_security_rule` | `direction`, `access`, `protocol`, `source_address_prefix`, `source_address_prefixes`, `destination_port_range`, `destination_port_ranges` |
| `google_compute_firewall` | `direction`, `disabled`, `source_ranges`, and `protocol` and `ports` in each `allow` block |

Rules that name a security group, a tag or a service account as the source
are not judged. Egress rules are not judged.

## Other checks

| Check | Severity | Resource type | Finding when |
|---|---|---|---|
| `public-access-block-disabled` | medium | `aws_s3_bucket_public_access_block` | Any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` is false or not set |
| `public-access-block-disabled` | medium | `AWS::S3::Bucket` | Any of the four flags under `PublicAccessBlockConfiguration` is explicitly false. A bucket with no such block is not flagged |
| `public-database` | high | `azurerm_mssql_firewall_rule`, `azurerm_postgresql_flexible_server_firewall_rule`, `azurerm_mysql_flexible_server_firewall_rule` | `start_ip_address` is `0.0.0.0` and `end_ip_address` is `255.255.255.255` |
| `db-open-to-azure-services` | medium | the same three types | Both addresses are `0.0.0.0`, the rule that admits all Azure services |
| `public-database` | high | `google_sql_database_instance` | An `authorized_networks` block under `settings.ip_configuration` has `value` `0.0.0.0/0` or `::/0` |
| `public-storage` | high | `google_storage_bucket_iam_member`, `google_storage_bucket_iam_binding` | `member` or `members` includes `allUsers` or `allAuthenticatedUsers` |
| `db-single-zone` | medium | `azurerm_postgresql_flexible_server`, `azurerm_mysql_flexible_server` | No `high_availability` block. Low when `mode` is `SameZone` |
| `single-instance` | low | `aws_instance`, `AWS::EC2::Instance`, `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`, `google_compute_instance` | Declared once. A literal `count` or `for_each` other than one instance is not flagged; an expression is "not evaluated" |
| `single-instance` | low | Kubernetes `Deployment`, `StatefulSet` | `spec.replicas` is 1 or absent, and no `HorizontalPodAutoscaler` in the scan targets it |

## Secrets written as literal values

`plaintext-secret` (high) fires when a name that looks like a secret holds a
non-empty literal string. The value is never printed.

- A name looks like a secret when, ignoring case, it ends in `password`,
  `passwd`, `secret`, `token`, `api_key`, `apikey`, `access_key`, `accesskey`,
  `secret_key`, `secretkey`, `private_key` or `privatekey`. The bare names
  `secret` and `token` and the CloudFormation property `ServiceToken` are
  excluded, because they usually hold a reference.
- Where it looks: every attribute of every Terraform resource, provider,
  module and locals block, including nested blocks and map values; the
  `default` of a Terraform variable with such a name; `.tfvars` files;
  CloudFormation resource properties and parameter defaults; Kubernetes
  documents; Compose services. Environment entries written as a name and
  value pair are matched on the name.
- Always treated as secrets when literal: `secret_string` on
  `aws_secretsmanager_secret_version`, `value` on `azurerm_key_vault_secret`,
  `secret_data` on `google_secret_manager_secret_version`, `SecretString` on
  `AWS::SecretsManager::Secret`, and `value` on an `aws_ssm_parameter` whose
  `type` is `SecureString`.
- Not flagged: expressions, empty strings, values that start with `$`
  (variable references in Compose and Kubernetes) or with `{{resolve:`
  (CloudFormation dynamic references).
- A Kubernetes `Secret` manifest with entries under `data` or `stringData` is
  one finding, unless the document has a top-level `sops` key.

This is a name-based check. It misses secrets stored under ordinary names and
inside heredocs, `jsonencode(...)` calls and user-data scripts. It is not a
replacement for a secret scanner.

## What is not checked

- IAM policies, role assignments and trust relationships. Read them by hand.
- Anything inside a module, behind a variable, or in a `dynamic` block.
- Terraform JSON syntax (`.tf.json`), Terraform state and plan files, ARM and
  Bicep templates, Pulumi and CDK source. For CDK, scan the synthesised
  templates (`cdk.out/*.template.json`).
- CloudFormation YAML that uses short tags such as `!Ref`. Convert it to JSON
  first.
- Helm charts and Kustomize overlays. Render them to plain manifests first.
- Kubernetes pod security, probes, resource limits and network policies.
- Aurora instance placement, ElastiCache, OpenSearch, Cosmos DB, Azure SQL
  and Cloud Spanner settings: these types are inventoried only.
- Whether a value is right for the workload: instance sizes, storage sizes,
  retention periods, scaling limits.
