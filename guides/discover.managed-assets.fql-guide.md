Falcon Query Language (FQL) - Search Managed Assets Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default)
• ! = not equal to
• > = greater than
• >= = greater than or equal
• < = less than
• <= = less than or equal
• ~ = text match (ignores case, spaces, punctuation)
• * = wildcard matching (not supported on all fields — see endpoint-specific notes below)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition (e.g., platform_name:'Windows'+status:'normal')
• , = OR condition (e.g., severity_name:'Critical',severity_name:'High')
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted. Relative dates must be lowercase ('now-7d' not 'NOW-7d').

=== AUTOMATIC FILTERING ===
This tool automatically filters for managed assets only by adding entity_type:'managed' to all queries.
You do not need to (and cannot) specify entity_type in your filter - it is always set to 'managed'.

=== WHAT THIS TOOL ADDS OVER falcon_search_hosts ===
Managed assets expose asset and configuration posture that the Hosts API does not carry:
drive encryption (encryption_status, unencrypted_drives), OS security settings
(os_security.* - Secure Boot, Credential Guard, IOMMU, VBS), and disk/memory/CPU capacity
and usage. Use falcon_search_hosts for sensor state (containment, sensor version, policies).

=== falcon_search_managed_assets FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|aid|String|Yes|Falcon agent ID (AID) of the managed asset - the same value that falcon_search_hosts and falcon_get_host_details return as the device ID. If you already have an aid in hand, filter on it: it is unique per sensor and pins exactly one host, whereas hostname can repeat across assets. You do not need to call the Hosts tools first - when starting from a general question, filter by whatever fields fit it. Ex: aid:'29fa15c9cebe4d3f90f4cbe0498e8c7a' Ex: aid:['29fa15c9cebe4d3f90f4cbe0498e8c7a','5c1e...']|
|id|String|Yes|Unique Discover asset ID. Distinct from aid; use aid to cross-reference the Hosts module. Ex: id:'5ddb0407bef249c19c7a975f17979a1f_ATDzldMcuDne...'|
|encryption_status|String|Yes|Overall drive-encryption status of the managed asset. Ex: encryption_status:'Encrypted' Ex: encryption_status:'Unencrypted'|
|unencrypted_drives|String|Yes|Drive letters/mount points that are not encrypted. Ex: unencrypted_drives:'C:' Ex: unencrypted_drives:['C:','D:']|
|unencrypted_drives_count|Number|Yes|Number of unencrypted drives on the asset. Ex: unencrypted_drives_count:>0 Ex: unencrypted_drives_count:0|
|number_of_disk_drives|Number|Yes|Total number of disk drives on the asset. Ex: number_of_disk_drives:>0 Ex: number_of_disk_drives:>=2|
|os_security.secure_boot_enabled_status|Boolean|Yes|Whether Secure Boot is currently enabled (true/false). Ex: os_security.secure_boot_enabled_status:true Ex: os_security.secure_boot_enabled_status:false|
|os_security.secure_boot_requested_status|Boolean|Yes|Whether Secure Boot has been requested (true/false). Ex: os_security.secure_boot_requested_status:true|
|os_security.credential_guard_status|Boolean|Yes|Whether Windows Credential Guard is enabled (true/false). Ex: os_security.credential_guard_status:true Ex: os_security.credential_guard_status:false|
|os_security.kernel_dma_protection_status|Boolean|Yes|Whether Kernel DMA Protection is enabled (true/false). Ex: os_security.kernel_dma_protection_status:true|
|os_security.iommu_protection_status|Boolean|Yes|Whether IOMMU protection is enabled (true/false). Ex: os_security.iommu_protection_status:true|
|os_security.virtualization_based_security_status|Boolean|Yes|Whether Virtualization-Based Security (VBS) is enabled (true/false). Ex: os_security.virtualization_based_security_status:true|
|used_disk_space|Number|Yes|Used disk space on the asset, in bytes. Note: use the greater-than operator; the '<' operator on this field can return a server error. Ex: used_disk_space:>0|
|total_disk_space|Number|Yes|Total disk space on the asset, in bytes. Ex: total_disk_space:>0|
|total_memory|Number|Yes|Total physical memory on the asset, in bytes. Ex: total_memory:>0|
|average_memory_usage|Number|Yes|Average memory usage of the asset. Ex: average_memory_usage:>0|
|average_processor_usage|Number|Yes|Average processor (CPU) usage of the asset. Ex: average_processor_usage:>0|
|platform_name|String|Yes|Operating system platform of the managed asset. Ex: platform_name:'Windows' Ex: platform_name:'Linux' Ex: platform_name:'Mac' Ex: platform_name:['Windows','Linux']|
|os_version|String|Yes|Operating system version of the managed asset. Ex: os_version:'Windows 10' Ex: os_version:*'Windows*'|
|hostname|String|Yes|Hostname of the managed asset. Ex: hostname:'PC-001' Ex: hostname:*'PC-*' Ex: hostname:['PC-001','PC-002']|
|product_type_desc|String|Yes|Product type description of the managed asset. Ex: product_type_desc:'Workstation' Ex: product_type_desc:'Server' Ex: product_type_desc:'Domain Controller'|
|criticality|String|Yes|Criticality level assigned to the managed asset. Ex: criticality:'Critical' Ex: criticality:'High' Ex: criticality:'Unassigned'|
|internet_exposure|String|Yes|Whether the managed asset is exposed to the internet. Ex: internet_exposure:'Yes' Ex: internet_exposure:'No' Ex: internet_exposure:['Yes','Pending']|
|external_ip|String|Yes|External IP address of the managed asset. Ex: external_ip:'192.0.2.1' Ex: external_ip:'192.0.2.0/24'|
|local_ip_addresses|String|Yes|Local IP addresses of the managed asset. Ex: local_ip_addresses:'10.0.1.100' Ex: local_ip_addresses:'192.168.1.0/24'|
|mac_addresses|String|Yes|MAC addresses of the managed asset. Ex: mac_addresses:'AA-BB-CC-DD-EE-FF' Ex: mac_addresses:*'AA-BB-CC*'|
|kernel_version|String|Yes|Kernel version of the managed asset. Ex: kernel_version:'5.4.0' Ex: kernel_version:*'5.4*'|
|system_manufacturer|String|Yes|System manufacturer of the managed asset. Ex: system_manufacturer:'Dell Inc.' Ex: system_manufacturer:*'Dell*'|
|system_product_name|String|Yes|System product name of the managed asset. Ex: system_product_name:'OptiPlex 7090' Ex: system_product_name:*'OptiPlex*'|
|country|String|Yes|Country where the managed asset is located. Ex: country:'United States of America' Ex: country:'Germany'|
|city|String|Yes|City where the managed asset is located. Ex: city:'New York' Ex: city:*'*'|
|discovering_by|String|Yes|Method by which the managed asset was discovered. Ex: discovering_by:'Passive' Ex: discovering_by:['Passive','Active']|
|first_seen_timestamp|Timestamp|Yes|Date and time when the managed asset was first seen. Ex: first_seen_timestamp:>'2024-01-01T00:00:00Z' Ex: first_seen_timestamp:>'now-90d'|
|last_seen_timestamp|Timestamp|Yes|Date and time when the managed asset was last seen. Ex: last_seen_timestamp:>'now-24h' Ex: last_seen_timestamp:>'now-30d'|

=== IMPORTANT NOTES ===
• entity_type:'managed' is automatically applied - do not include in your filter
• aid is the same identifier as the device ID returned by falcon_search_hosts / falcon_get_host_details
• If you already have an aid, prefer it - it is unique per sensor and pins exactly one host (hostname can be shared). You do not need to fetch an aid first; when starting from a general question, filter by whatever fields fit it
• os_security.* fields are booleans - use true/false (no quotes), not 'Enabled'/'Disabled'
• Numeric fields (disk/memory/CPU) work with the greater-than operator (e.g. :>0); the '<' operator on disk-space fields can return a server error
• Encryption and os_security fields are populated only on assets that report that data (mainly Windows); other assets may omit these fields
• Use single quotes around string values: 'value'
• Use square brackets for exact matches and multiple values: ['value1','value2']
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'

=== COMMON FILTER EXAMPLES ===
• Look up a known host by its device ID (aid): aid:'29fa15c9cebe4d3f90f4cbe0498e8c7a'
• Find unencrypted assets: encryption_status:'Unencrypted'
• Find assets with unencrypted drives: unencrypted_drives_count:>0
• Find assets without Secure Boot: os_security.secure_boot_enabled_status:false
• Find assets with Credential Guard enabled: os_security.credential_guard_status:true
• Find Windows assets: platform_name:'Windows'
• Find critical assets: criticality:'Critical'
• Find internet-exposed assets: internet_exposure:'Yes'
• Find recently seen assets: last_seen_timestamp:>'now-24h'

=== COMPLEX QUERY EXAMPLES ===
• Unencrypted Windows workstations: platform_name:'Windows'+product_type_desc:'Workstation'+encryption_status:'Unencrypted'
• Critical internet-exposed servers: criticality:'Critical'+product_type_desc:'Server'+internet_exposure:'Yes'
• Windows assets missing Credential Guard: platform_name:'Windows'+os_security.credential_guard_status:false
