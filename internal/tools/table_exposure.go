package tools

const shieldGuide = "falcon://shield/search/query-guide"

var (
	vulnBrief = []string{"id", "aid", "status", "cve.id", "cve.severity", "cve.exprt_rating", "cve.base_score",
		"cve.is_cisa_kev", "host_info.hostname", "host_info.platform_name", "created_timestamp", "updated_timestamp"}
	cspmAssetBrief = []string{"id", "resource_name", "resource_type", "cloud_provider", "account_id", "region", "service",
		"active", "updated_at", "cloud_context.publicly_exposed", "cloud_context.detections.highest_severity"}
	containerBrief = []string{"container_id", "container_name", "cluster_name", "namespace", "pod_name",
		"image_repository", "image_tag", "running_status", "image_vulnerability_count", "last_seen"}
	imageVulnBrief = []string{"cve_id", "severity", "cvss_score", "cps_current_rating", "images_impacted", "packages_impacted"}
	iomBrief       = []string{"id", "evaluation.severity", "evaluation.status", "evaluation.first_detected", "evaluation.last_detected",
		"cloud.provider", "resource.service", "resource.resource_id", "rule.name"}
	riskBrief = []string{"id", "rule_name", "severity", "status", "asset_name", "asset_type", "cloud_provider", "account_id", "first_seen", "last_seen"}
)

var exposureTools = []Tool{
	{Name: "falcon_vulnerability", Group: "exposure", Title: "Vulnerabilities",
		Description: "Falcon Spotlight vulnerabilities on hosts, and vulnerabilities in serverless functions.",
		Actions: []Action{
			{Name: "search", Help: "host vulnerabilities matching filter (required), e.g. status:'open'+cve.severity:'CRITICAL'; sort e.g. updated_timestamp.desc. params facet adds remediation or evaluation_logic.", Kind: Search,
				Op: "combinedQueryVulnerabilities", Paging: After, Brief: vulnBrief,
				Set: map[string][]string{"facet": {"cve", "host_info"}}, Params: []string{"facet"},
				Guide: "falcon://spotlight/vulnerabilities/fql-guide"},
			{Name: "search_serverless", Help: "serverless function vulnerabilities as one SARIF document, matching filter (required), e.g. cloud_provider:'aws'; params limit, offset, sort.", Kind: Aggregate,
				Op: "GetCombinedVulnerabilitiesSARIF", Params: []string{"limit", "offset", "sort"},
				Guide: "falcon://serverless/vulnerabilities/fql-guide"},
		}},
	{Name: "falcon_cloud", Group: "exposure", Title: "Cloud security",
		Description: "Falcon Cloud Security: cloud asset inventory, Kubernetes containers and image vulnerabilities, cloud insights, misconfiguration (IOM) findings, suppression rules, risks and cloud groups.",
		Actions: []Action{
			// ponytail: offset paging stops at 10,000 assets (a Falcon limit); past that needs after-paging with hydration.
			{Name: "search_cspm_assets", Help: "cloud assets (EC2, VPC, S3, ...) matching filter, e.g. cloud_provider:'aws'; sort e.g. updated_at.desc. Records are large: keep fields narrow.", Kind: Search,
				Op: "cloud_security_assets_queries", Hydrate: "cloud_security_assets_entities_get", MaxLimit: 100, Brief: cspmAssetBrief,
				Guide: "falcon://cloud/cspm-assets/fql-guide"},
			{Name: "search_kubernetes_containers", Help: "Kubernetes containers matching filter, e.g. cluster_name:'prod'+running_status:true; sort e.g. last_seen.desc.", Kind: Search,
				Op: "ReadContainerCombined", Brief: containerBrief, Guide: "falcon://cloud/kubernetes-containers/fql-guide"},
			{Name: "count_kubernetes_containers", Help: "how many Kubernetes containers match filter.", Kind: Aggregate,
				Op: "ReadContainerCount", Guide: "falcon://cloud/kubernetes-containers/fql-guide"},
			{Name: "search_images_vulnerabilities", Help: "container image vulnerabilities matching filter, e.g. cvss_score:>5; sort e.g. cvss_score.desc.", Kind: Search,
				Op: "ReadCombinedVulnerabilities", MaxLimit: 100, Brief: imageVulnBrief, Guide: "falcon://cloud/images-vulnerabilities/fql-guide"},
			{Name: "search_insights", Help: "assets with insight facts matching filter, e.g. insights.id:['publiclyExposedToTheInternet']+insights.boolean_value:true; take insight ids from list_insight_definitions.", Kind: Search,
				Op: "cloud_security_assets_queries", Hydrate: "cloud_security_assets_entities_get", MaxLimit: 100,
				Brief: []string{"id", "resource_name", "resource_type", "cloud_provider", "account_id", "region", "service_category", "cloud_context.insights.external"},
				Guide: "falcon://cloud/cloud-insights/fql-guide"},
			{Name: "get_asset_insights", Help: "full assets by asset id (ids); they are large, so pass fields e.g. [id, resource_name, cloud_context.insights].", Kind: Get,
				Op: "cloud_security_assets_entities_get"},
			{Name: "list_insight_definitions", Help: "the insight catalog: one rule per insight and resource type, with insight_id and category; narrow with filter e.g. rule_category:'Identity'.", Kind: Search,
				Op: "QueryRule", Hydrate: "GetRule", MaxLimit: 100, Filter: "rule_domain:'CSPM'+rule_subdomain:'Insight'",
				Brief: []string{"uuid", "insight_id", "name", "category", "provider", "resource_type", "description"}},
			{Name: "search_iom_findings", Help: "misconfiguration findings (one rule failing on one resource) matching filter, e.g. severity:'critical'+status:'non-compliant'; severity.asc sorts most severe first.", Kind: Search,
				Op: "cspm_evaluations_iom_queries", Hydrate: "cspm_evaluations_iom_entities", MaxLimit: 100, Brief: iomBrief,
				Guide: "falcon://cloud/cspm-iom-findings/fql-guide"},
			{Name: "search_suppression_rules", Help: "IOM suppression rules matching filter (name, domain, suppression_reason, ...).", Kind: Search,
				Op: "QuerySuppressionRules", Hydrate: "GetSuppressionRules", MaxLimit: 50,
				Brief: []string{"id", "name", "description", "domain", "subdomain", "suppression_reason", "suppression_expiration_date", "created_by", "created_at", "disabled"}},
			{Name: "search_risks", Help: "cloud risks (IOMs and IOAs rolled up per asset) matching filter, e.g. severity:'Critical'+status:'Open'; sort e.g. severity.desc.", Kind: Search,
				Op: "combined_cloud_risks", Brief: riskBrief, Guide: "falcon://cloud/cloud-risks/fql-guide"},
			{Name: "search_groups", Help: "cloud groups matching filter (name, description, cloud_provider, account_id, region, environment, business_unit); sort e.g. name.asc.", Kind: Search,
				Op: "ListCloudGroupsExternal", Brief: []string{"id", "name", "description", "business_unit", "business_impact", "environment", "created_at", "updated_at"}},
			{Name: "get_groups", Help: "full cloud groups by id (ids).", Kind: Get, Op: "ListCloudGroupsByIDExternal"},
		}},
	// Shield takes named params, not FQL. Its records' field names are unverified, so its searches have no brief set; results are still byte-capped.
	{Name: "falcon_shield", Group: "exposure", Title: "SaaS Security",
		Description: "Falcon Shield (SaaS Security): posture checks, alerts, activity and inventory of connected SaaS apps. Takes named params, not FQL; the guide lists their values.",
		Actions: []Action{
			{Name: "search_checks", Help: "posture checks; params id, status (Passed|Failed|Dismissed|Pending|Can't Run|Stale), impact (Low|Medium|High), integration_id, compliance, check_type, check_tags, business_owner, org_domain.", Kind: Search,
				NoFilter: true, Op: "GetSecurityChecksV3", Params: []string{"id", "status", "impact", "integration_id", "compliance", "check_type", "check_tags", "business_owner", "org_domain"}, Guide: shieldGuide},
			{Name: "get_check_affected_entities", Help: "entities failing check id.", Kind: Search, NoFilter: true, Op: "GetSecurityCheckAffectedV3", Param: "id"},
			{Name: "get_posture_metrics", Help: "posture score and check counts; params status, impact (1|2|3 = Low|Medium|High), integration_id, compliance, check_type, check_tags, business_owner, org_domain.", Kind: Aggregate,
				NoFilter: true, Op: "GetMetricsV3", Params: []string{"status", "impact", "integration_id", "compliance", "check_type", "check_tags", "business_owner", "org_domain"}, Guide: shieldGuide},
			{Name: "get_check_compliance", Help: "compliance framework controls of a check; params id (required).", Kind: Aggregate,
				NoFilter: true, Op: "GetSecurityCheckComplianceV3", Params: []string{"id"}},
			{Name: "search_alerts", Help: "SaaS alerts; params id, type (configuration_drift|check_degraded|integration_failure|threat), integration_id, from_date, to_date (YYYY-MM-DD), ascending.", Kind: Search,
				NoFilter: true, Op: "GetAlertsV3", Params: []string{"id", "type", "integration_id", "from_date", "to_date", "ascending"}, Guide: shieldGuide},
			{Name: "get_activity_monitor", Help: "activity events, kept 180 days, unpaged; params integration_id, actor, category (Events|Threat|IoC), projection, from_date, to_date (ISO 8601; 24h max with integration_id/category/actor), limit, skip.", Kind: Aggregate,
				NoFilter: true, Op: "GetActivityMonitorV3", Params: []string{"integration_id", "actor", "category", "projection", "from_date", "to_date", "limit", "skip"}, Guide: shieldGuide},
			{Name: "search_users", Help: "users of connected SaaS apps; params integration_id, email, privileged_only.", Kind: Search,
				NoFilter: true, Op: "GetUserInventoryV3", Params: []string{"integration_id", "email", "privileged_only"}},
			{Name: "search_devices", Help: "devices seen by connected SaaS apps; params integration_id, email, privileged_only, unassociated_devices.", Kind: Search,
				NoFilter: true, Op: "GetDeviceInventoryV3", Params: []string{"integration_id", "email", "privileged_only", "unassociated_devices"}},
			{Name: "search_apps", Help: "third-party apps connected to SaaS; params type, status (approved|in review|rejected|unclassified), access_level, scopes, users, groups, last_activity ('was N'|'was not N' days), integration_id.", Kind: Search,
				NoFilter: true, Op: "GetAppInventory", Params: []string{"type", "status", "access_level", "scopes", "users", "groups", "last_activity", "integration_id"}, Guide: shieldGuide},
			{Name: "get_app_users", Help: "users of an app; params item_id (required, 'integration_id|||app_id').", Kind: Aggregate,
				NoFilter: true, Op: "GetAppInventoryUsers", Params: []string{"item_id"}},
			{Name: "search_data_shares", Help: "shared files and resources; params integration_id, resource_type, access_level, resource_name, resource_owner, resource_owner_enabled, password_protected, last_accessed, last_modified ('was N'|'was not N'), unmanaged_domain.", Kind: Search,
				NoFilter: true, Op: "GetAssetInventoryV3", Params: []string{"integration_id", "resource_type", "access_level", "resource_name", "resource_owner", "resource_owner_enabled", "password_protected", "last_accessed", "last_modified", "unmanaged_domain"}, Guide: shieldGuide},
			{Name: "get_integrations", Help: "connected SaaS integrations and their ids; params saas_id.", Kind: Aggregate, NoFilter: true, Op: "GetIntegrationsV3", Params: []string{"saas_id"}},
			{Name: "get_system_users", Help: "Falcon Shield console administrators.", Kind: Aggregate, NoFilter: true, Op: "GetSystemUsersV3"},
			{Name: "get_supported_saas", Help: "SaaS platforms Falcon Shield can connect.", Kind: Aggregate, NoFilter: true, Op: "GetSupportedSaasV3"},
			{Name: "get_system_logs", Help: "Falcon Shield audit log, kept 90 days; params from_date, to_date (YYYY-MM-DD), total_count.", Kind: Search,
				NoFilter: true, Op: "GetSystemLogsV3", Params: []string{"from_date", "to_date", "total_count"}},
		}},
	{Name: "falcon_data_protection", Group: "exposure", Title: "Data protection",
		Description: "Falcon Data Protection configuration: classifications, policies and content patterns.",
		Actions: []Action{
			{Name: "search_classifications", Help: "classifications matching filter; sort name|created_at|modified_at.", Kind: Search,
				Op: "queries_classification_get_v2", Hydrate: "entities_classification_get_v2",
				Brief: []string{"id", "name", "created_at", "modified_at", "created_by", "modified_by"}, Guide: "falcon://data-protection/classifications/fql-guide"},
			{Name: "search_policies", Help: "policies matching filter; params platform_name (required: win|mac); sort e.g. precedence.asc.", Kind: Search,
				Op: "queries_policy_get_v2", Hydrate: "entities_policy_get_v2", Params: []string{"platform_name"},
				Brief: []string{"id", "name", "description", "platform_name", "precedence", "is_enabled", "is_default", "modified_at"}, Guide: "falcon://data-protection/policies/fql-guide"},
			{Name: "search_content_patterns", Help: "content patterns (regexes for sensitive data) matching filter; sort e.g. name.asc.", Kind: Search,
				Op: "queries_content_pattern_get_v2", Hydrate: "entities_content_pattern_get",
				Brief: []string{"id", "name", "type", "category", "region", "example", "deleted"}, Guide: "falcon://data-protection/content-patterns/fql-guide"},
		}},
}
