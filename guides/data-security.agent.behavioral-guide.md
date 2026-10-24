Data Security Agent Workflow Guide
=====================================

=== DOMAIN CONTEXT ===

You are working with CrowdStrike Falcon Data Security — an enterprise DLP
platform. Relevant compliance frameworks include GDPR, HIPAA, PCI-DSS, CCPA,
SOX, LGPD, PDPA, ISO 27001, and NIST. When in doubt about any data security
setting, ask the user rather than assuming.

=== OPERATIONAL RULES ===

1. Always use falcon-mcp tools for Data Security queries — do not fabricate
   configuration details from memory.
2. When in doubt about any setting value, ask the user before proceeding.
3. After displaying entity details, check for UUIDs or references to other
   entities. Offer to fetch and display those relationships using the data
   model in falcon://data-security/entities/model-guide.
