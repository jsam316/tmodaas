// TModaaS control catalog — generic + vendor-specific hardening controls per asset class.
window.TMODAAS_CATALOG = [
  {
    key: 'firewall', label: 'Firewall', layer: 'Security', inPath: true,
    vendors: {
      'Fortinet FortiGate': [
        { t: 'Enforce least-privilege firewall policies', d: 'Apply a default-deny posture on FortiGate. Remove any-to-any rules, scope policies to named address/service objects and review the rule base quarterly.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High' },
        { t: 'Enable IPS and web filtering profiles', d: 'Attach IPS, antivirus and web filtering security profiles to all internet-facing policies and keep FortiGuard signatures on automatic update.', iso: 'A.12.6.1', pci: '11.4', sev: 'High' },
        { t: 'Harden management access', d: 'Restrict admin access to trusted hosts, disable HTTP/Telnet management, enforce MFA for administrator accounts and use a dedicated management VLAN.', iso: 'A.9.4.2', pci: '8.3.1', sev: 'High' },
        { t: 'Patch FortiOS promptly', d: 'Subscribe to Fortinet PSIRT advisories and apply firmware updates within a defined maintenance window; several FortiOS SSL-VPN CVEs are actively exploited.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Centralise and retain logs', d: 'Forward traffic and event logs to FortiAnalyzer or a central syslog/SIEM and retain them for at least 12 months.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium' },
      ],
      'Palo Alto NGFW': [
        { t: 'Use App-ID based least-privilege rules', d: 'Write security policies on App-ID rather than ports, remove overly-broad "application: any" rules and enable policy usage review.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High' },
        { t: 'Attach Threat Prevention profiles', d: 'Apply vulnerability protection, anti-spyware and antivirus profiles to all allow rules; keep content updates on a daily schedule.', iso: 'A.12.6.1', pci: '11.4', sev: 'High' },
        { t: 'Isolate the management interface', d: 'Place the management interface on a dedicated out-of-band network, permit access only from admin subnets and enforce MFA via SAML/RADIUS.', iso: 'A.9.4.2', pci: '8.3.1', sev: 'High' },
        { t: 'Keep PAN-OS at a preferred release', d: 'Track Palo Alto security advisories and stay on a preferred/fixed PAN-OS release; validate HA pairs before and after upgrades.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Enable decryption where lawful', d: 'Apply SSL forward proxy/inbound inspection on high-risk flows so threat profiles can inspect encrypted traffic; log decryption exclusions.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium' },
      ],
    },
  },
  {
    key: 'loadBalancer', label: 'Load Balancer', layer: 'Infrastructure', inPath: true,
    vendors: {
      'F5 BIG-IP': [
        { t: 'Terminate TLS with a strong cipher suite', d: 'Use client-SSL profiles limited to TLS 1.2+, disable weak ciphers and renegotiation, and automate certificate rotation.', iso: 'A.10.1.1', pci: '4.1', sev: 'High' },
        { t: 'Lock down the management plane', d: 'Restrict access to the management interface and self-IPs (port lockdown: allow none/custom), and never expose the TMUI to the internet — see CVE-2020-5902.', iso: 'A.9.4.2', pci: '1.3', sev: 'High' },
        { t: 'Deploy WAF policy on public virtual servers', d: 'Apply an ASM/Advanced WAF policy in blocking mode for internet-facing applications, tuned from a learning period.', iso: 'A.14.1.2', pci: '6.6', sev: 'High' },
        { t: 'Patch TMOS on a defined cadence', d: 'Track F5 quarterly security notifications and apply point releases; test on the standby unit and fail over.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Ship logs to remote analytics', d: 'Configure high-speed logging of LTM/ASM events to a SIEM; alert on config changes and failed logins.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium' },
      ],
      'Citrix ADC': [
        { t: 'Remediate known ADC CVEs immediately', d: 'Citrix ADC/Gateway appliances are frequent mass-exploitation targets (e.g. CVE-2019-19781, CVE-2023-3519); apply security builds as an emergency change.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Replace default credentials and enforce MFA', d: 'Change the default nsroot password, integrate admin auth with LDAP/RADIUS and require MFA for management access.', iso: 'A.9.2.4', pci: '2.1', sev: 'High' },
        { t: 'Restrict NSIP management access', d: 'Bind management to a dedicated subnet/VLAN, block internet access to the NSIP and disable unneeded management services.', iso: 'A.9.4.2', pci: '1.3', sev: 'High' },
        { t: 'Harden TLS profiles', d: 'Enforce TLS 1.2+ front-end and back-end profiles, disable SSLv3/weak ciphers and enable HSTS on content-switching virtual servers.', iso: 'A.10.1.1', pci: '4.1', sev: 'Medium' },
        { t: 'Enable AppFirewall and audit logging', d: 'Use Citrix Web App Firewall profiles on exposed virtual servers and forward audit/syslog events to a central collector.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium' },
      ],
    },
  },
  {
    key: 'hypervisor', label: 'Hypervisor / Cloud', layer: 'Infrastructure', inPath: false,
    vendors: {
      'VMware ESXi': [
        { t: 'Enable lockdown mode', d: 'Run hosts in normal or strict lockdown mode so all operations flow through vCenter, and disable the ESXi Shell and SSH except during maintenance.', iso: 'A.9.4.2', pci: '2.2.4', sev: 'High' },
        { t: 'Patch hosts via vLCM baselines', d: 'Apply VMware security patches through Lifecycle Manager images/baselines; ESXi ransomware campaigns target unpatched hosts.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Isolate management and vMotion networks', d: 'Keep management, vMotion and storage traffic on dedicated non-routable VLANs, separate from VM guest networks.', iso: 'A.13.1.3', pci: '1.3.6', sev: 'High' },
        { t: 'Use Secure Boot and TPM attestation', d: 'Enable UEFI Secure Boot for ESXi and host attestation with TPM 2.0 so unsigned VIBs and tampered boot chains are rejected.', iso: 'A.14.2.4', pci: '11.5', sev: 'Medium' },
        { t: 'Forward host logs and NTP-sync', d: 'Point all hosts at a central syslog target and authoritative NTP so events are complete and correlatable.', iso: 'A.12.4.4', pci: '10.4', sev: 'Medium' },
      ],
      'Microsoft Hyper-V': [
        { t: 'Run hosts on Server Core', d: 'Minimise the attack surface by installing the Hyper-V role on Server Core with no other roles or workloads on the host partition.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'High' },
        { t: 'Use shielded VMs for sensitive workloads', d: 'Deploy a guarded fabric with Host Guardian Service; shielded VMs encrypt state and block console/PowerShell Direct access from host admins.', iso: 'A.10.1.1', pci: '3.4', sev: 'Medium' },
        { t: 'Patch hosts through a managed channel', d: 'Apply monthly cumulative updates through WSUS/Azure Update Manager with cluster-aware updating for failover clusters.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Separate the management network', d: 'Use a dedicated management VLAN and vSwitch; block VM guest networks from reaching host management endpoints.', iso: 'A.13.1.3', pci: '1.3.6', sev: 'High' },
        { t: 'Constrain admin rights with JEA', d: 'Delegate host administration through Just Enough Administration roles instead of broad local Administrators membership.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium' },
      ],
      'Nutanix AHV': [
        { t: 'Enable cluster lockdown mode', d: 'Enforce key-based SSH only (or disable remote shell entirely) with Nutanix cluster lockdown, and change default CVM/host credentials.', iso: 'A.9.4.2', pci: '2.1', sev: 'High' },
        { t: 'Keep AOS/AHV current with LCM', d: 'Use Life Cycle Manager to apply AOS, AHV and firmware security updates; review Nutanix security advisories monthly.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Enable data-at-rest encryption', d: 'Turn on cluster-level software encryption or SED drives with an external KMS to protect data on removed disks.', iso: 'A.10.1.1', pci: '3.4', sev: 'Medium' },
        { t: 'Enforce Prism RBAC with MFA', d: 'Integrate Prism with AD/SAML, assign least-privilege roles and require MFA for administrative logins.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High' },
        { t: 'Forward audit logs to a SIEM', d: 'Configure rsyslog forwarding for CVM and AHV audit events and alert on configuration changes.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium' },
      ],
      'Microsoft Azure': [
        { t: 'Enable Microsoft Defender for Cloud', d: 'Turn on Defender plans for servers, SQL and storage; remediate recommendations to raise Secure Score on the subscription.', iso: 'A.12.6.1', pci: '11.2', sev: 'High' },
        { t: 'Apply least-privilege NSGs', d: 'Restrict inbound rules on network security groups to required ports/sources only; deny direct RDP/SSH from the internet, use Bastion.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High' },
        { t: 'Require MFA and PIM for privileged roles', d: 'Enforce MFA via Conditional Access and use Privileged Identity Management for just-in-time activation of Owner/Contributor roles.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High' },
        { t: 'Enforce baselines with Azure Policy', d: 'Assign the Microsoft cloud security benchmark initiative to audit/deny drift from the hardening baseline across resources.', iso: 'A.18.2.3', pci: '2.2', sev: 'Medium' },
        { t: 'Retain activity and resource logs', d: 'Route activity logs and diagnostics to Log Analytics with at least 12 months retention and alert on privileged operations.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium' },
      ],
    },
  },
  {
    key: 'operatingSystem', label: 'Operating System', layer: 'Infrastructure', inPath: false,
    vendors: {
      'Windows Server': [
        { t: 'Apply a CIS/STIG hardening baseline', d: 'Deploy CIS Benchmark or Microsoft security baseline GPOs and monitor drift with a configuration-compliance tool.', iso: 'A.12.5.1', pci: '2.2', sev: 'High' },
        { t: 'Patch monthly with defined SLAs', d: 'Deploy cumulative updates through WSUS/Intune within 30 days (7 days for critical, internet-facing systems).', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Randomise local admin passwords with LAPS', d: 'Use Windows LAPS so every server has a unique, rotated local administrator password stored in AD/Entra.', iso: 'A.9.2.4', pci: '8.2.6', sev: 'High' },
        { t: 'Disable legacy protocols', d: 'Remove SMBv1, disable NTLMv1 and LLMNR/NetBIOS name resolution, and enforce SMB signing.', iso: 'A.13.1.2', pci: '2.2.3', sev: 'Medium' },
        { t: 'Enable EDR and audit forwarding', d: 'Run Defender for Endpoint (or equivalent EDR) and forward Security event logs to a SIEM with alerting on privilege changes.', iso: 'A.12.4.1', pci: '10.6', sev: 'High' },
      ],
      'Linux': [
        { t: 'Harden to the CIS benchmark', d: 'Apply the distribution CIS benchmark (partition options, sysctl, service removal) and verify with OpenSCAP or Lynis.', iso: 'A.12.5.1', pci: '2.2', sev: 'High' },
        { t: 'Keep SELinux/AppArmor enforcing', d: 'Run mandatory access control in enforcing mode; never disable it to "fix" application issues — write targeted policies instead.', iso: 'A.9.4.1', pci: '2.2.5', sev: 'Medium' },
        { t: 'Restrict SSH access', d: 'Permit key-based authentication only, disable root login, and gate SSH behind a bastion or allow-listed subnets.', iso: 'A.9.4.2', pci: '8.2', sev: 'High' },
        { t: 'Automate security updates', d: 'Enable unattended security upgrades (or a patch pipeline) so kernel and package CVEs are closed within SLA.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Enable auditd and central logging', d: 'Audit privileged commands and identity changes with auditd rules and forward journals/syslog to a central collector.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium' },
      ],
    },
  },
  {
    key: 'web', label: 'Web Server', layer: 'Application', inPath: true,
    vendors: {
      'Apache HTTP Server': [
        { t: 'Suppress version disclosure', d: 'Set ServerTokens Prod and ServerSignature Off so httpd version and modules are not leaked in headers and error pages.', iso: 'A.12.5.1', pci: '2.2.4', sev: 'Medium' },
        { t: 'Enforce modern TLS', d: 'Allow TLS 1.2+ only with a curated cipher list, enable HSTS and redirect all HTTP to HTTPS.', iso: 'A.10.1.1', pci: '4.1', sev: 'High' },
        { t: 'Deploy ModSecurity with OWASP CRS', d: 'Run mod_security with the OWASP Core Rule Set in blocking mode to mitigate injection and common web attacks.', iso: 'A.14.1.2', pci: '6.6', sev: 'High' },
        { t: 'Run with least privilege', d: 'Run workers as a dedicated non-root user, disable directory indexing and unused modules (autoindex, status, cgi).', iso: 'A.9.4.4', pci: '2.2.2', sev: 'Medium' },
        { t: 'Patch httpd and centralise access logs', d: 'Track Apache security releases, patch within SLA and forward access/error logs for anomaly detection.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
      ],
      'Microsoft IIS': [
        { t: 'Remove unused modules and handlers', d: 'Uninstall features not required by the application (WebDAV, CGI, FTP) and remove sample/default sites.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'Medium' },
        { t: 'Enforce TLS 1.2+ via Schannel', d: 'Disable SSL 3.0/TLS 1.0/1.1 and weak ciphers at the Schannel level; enable HSTS on production bindings.', iso: 'A.10.1.1', pci: '4.1', sev: 'High' },
        { t: 'Configure request filtering', d: 'Set maxAllowedContentLength, block double-escaping and high-bit characters, and filter dangerous verbs and file extensions.', iso: 'A.14.1.2', pci: '6.5', sev: 'Medium' },
        { t: 'Isolate application pools', d: 'Run each site in its own app pool under a virtual/least-privilege identity so one compromised app cannot read another\u2019s content.', iso: 'A.9.4.4', pci: '2.2.1', sev: 'High' },
        { t: 'Enable enhanced logging and patching', d: 'Log with W3C extended fields including X-Forwarded-For, forward to a SIEM, and patch IIS/ASP.NET via monthly Windows updates.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium' },
      ],
      'Nginx': [
        { t: 'Hide server tokens', d: 'Set server_tokens off and remove identifying headers so version details are not exposed to scanners.', iso: 'A.12.5.1', pci: '2.2.4', sev: 'Medium' },
        { t: 'Harden TLS configuration', d: 'Serve TLS 1.2/1.3 only with modern ciphers, OCSP stapling and HSTS; automate certificate renewal.', iso: 'A.10.1.1', pci: '4.1', sev: 'High' },
        { t: 'Apply rate limiting', d: 'Use limit_req/limit_conn zones on login and API endpoints to blunt brute-force and application-layer DoS.', iso: 'A.13.1.2', pci: '6.5', sev: 'Medium' },
        { t: 'Run workers as non-root', d: 'Drop worker privileges to a dedicated user, disable autoindex and restrict access to hidden/dot files.', iso: 'A.9.4.4', pci: '2.2.2', sev: 'Medium' },
        { t: 'Track security releases and add WAF', d: 'Patch nginx security releases within SLA and front public apps with ModSecurity/NAXSI or a cloud WAF.', iso: 'A.12.6.1', pci: '6.6', sev: 'High' },
      ],
    },
  },
  {
    key: 'middleware', label: 'Middleware', layer: 'Application', inPath: true,
    vendors: {
      'Oracle WebLogic': [
        { t: 'Apply quarterly Critical Patch Updates', d: 'WebLogic is a recurring target for RCE exploits (T3/IIOP deserialisation); apply Oracle CPUs the quarter they are released.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Block T3/IIOP from untrusted networks', d: 'Filter or disable the T3, T3S and IIOP protocols at the network edge; expose only HTTPS through the web tier.', iso: 'A.13.1.1', pci: '1.3', sev: 'High' },
        { t: 'Restrict the administration console', d: 'Bind the admin console/port to a management network, rename the default weblogic account and enforce strong admin credentials.', iso: 'A.9.4.2', pci: '8.2', sev: 'High' },
        { t: 'Encrypt tier-to-tier traffic', d: 'Enable TLS between the web tier, WebLogic and the database, including JDBC over TLS, with production-mode SSL enforcement.', iso: 'A.10.1.1', pci: '4.1', sev: 'Medium' },
        { t: 'Run with least-privilege service accounts', d: 'Run managed servers under dedicated OS accounts with no interactive login and enable WebLogic auditing to a central log.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium' },
      ],
    },
  },
  {
    key: 'database', label: 'Database', layer: 'Application', inPath: true,
    vendors: {
      'Oracle Database': [
        { t: 'Apply quarterly CPU patches', d: 'Track Oracle Critical Patch Updates and apply database security patches within the quarter, including OJVM components.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Encrypt data with TDE', d: 'Enable Transparent Data Encryption for tablespaces holding sensitive data and manage keys in an external keystore.', iso: 'A.10.1.1', pci: '3.4', sev: 'High' },
        { t: 'Lock down default accounts', d: 'Lock and expire unused default schemas, enforce password profiles with complexity and failed-login limits.', iso: 'A.9.2.4', pci: '2.1', sev: 'High' },
        { t: 'Enable unified auditing', d: 'Audit privileged actions, logons and schema changes with Unified Auditing and forward records to a SIEM.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium' },
        { t: 'Encrypt client-database traffic', d: 'Enforce native network encryption or TLS for all client and application connections to the listener.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium' },
      ],
      'Microsoft SQL Server': [
        { t: 'Patch with latest CU/GDR', d: 'Apply SQL Server cumulative updates and security GDRs on a defined cadence; unsupported versions must be upgraded.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Enable TDE and backup encryption', d: 'Turn on Transparent Data Encryption for databases with sensitive data and encrypt backups with a protected certificate.', iso: 'A.10.1.1', pci: '3.4', sev: 'High' },
        { t: 'Disable or rename the sa account', d: 'Prefer Windows/Entra authentication, disable mixed mode where possible and disable or rename sa with a strong password.', iso: 'A.9.2.4', pci: '2.1', sev: 'High' },
        { t: 'Force encrypted connections', d: 'Configure the instance to require TLS 1.2+ for client connections with a CA-issued certificate.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium' },
        { t: 'Enable SQL Audit', d: 'Audit logins, permission changes and access to sensitive objects with server/database audit specifications shipped to a SIEM.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium' },
      ],
      'PostgreSQL': [
        { t: 'Stay on patched minor releases', d: 'Apply PostgreSQL minor version updates promptly — they are drop-in and carry the security fixes for supported majors.', iso: 'A.12.6.1', pci: '6.2', sev: 'High' },
        { t: 'Use SCRAM-SHA-256 authentication', d: 'Set password_encryption to scram-sha-256 and migrate any md5 credentials; never use trust auth beyond local dev.', iso: 'A.9.4.2', pci: '8.2.1', sev: 'High' },
        { t: 'Tighten pg_hba.conf', d: 'Scope host entries to specific databases, roles and CIDR ranges; require TLS (hostssl) for remote connections.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High' },
        { t: 'Apply role-based least privilege', d: 'Grant privileges through roles, revoke default PUBLIC schema rights and separate application, migration and admin roles.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium' },
        { t: 'Log with pgAudit', d: 'Enable pgaudit for DDL and role changes, log connections and forward logs to central analysis.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium' },
      ],
    },
  },
];
