Data Security Entity Relationship Model
==========================================

Policies reference Classifications by ID; Classifications combine detection
criteria (Content Patterns, File Types, Web Origins, Sensitivity Labels) with
response Rules. Use search/get tools to resolve referenced IDs.

Policy  (HOW to respond)
└── references one or more Classifications
        ├── WHAT to detect — any combination of:
        │     ├── Content Patterns (content): regex-based data pattern detectors
        │     ├── File Paths (context): where data is stored/named (glob syntax)
        │     ├── File Types (context): true file type, regardless of extension
        │     ├── Web Origins (context): where data originated from
        │     └── Sensitivity (MIP) Labels (context): Microsoft Information Protection labels
        └── one or more Rules  (WHO / WHICH channels / WHAT action)
              ├── Egress Channels: USB, Printer, Web Upload, Local Application
              ├── User Scope: all users OR specific AD Users/Groups (by SID)
              └── Response Action: block, allow, or justify

When displaying a policy or classification, offer to drill into referenced
entity IDs (classifications, content patterns, web locations, etc.) and
present the relationships using the tree structure above.

Per-entity FQL guides
---------------------
Before composing a `filter`, read the guide for the entity_type you are
searching:

  classification          -> falcon://data-security/classifications/fql-guide
  policy                  -> falcon://data-security/policies/fql-guide
  content_pattern         -> falcon://data-security/content-patterns/fql-guide
  cloud_application       -> falcon://data-security/cloud-applications/fql-guide
  enterprise_account      -> falcon://data-security/enterprise-accounts/fql-guide
  web_location            -> falcon://data-security/web-locations/fql-guide
  local_application       -> falcon://data-security/local-applications/fql-guide
  local_application_group -> falcon://data-security/local-application-groups/fql-guide
  sensitivity_label       -> falcon://data-security/sensitivity-labels/fql-guide
  file_type               -> falcon://data-security/file-types/fql-guide
