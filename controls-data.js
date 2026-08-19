// TModaaS control catalog — generic + vendor-specific hardening controls per asset class.
// `cmd` holds a representative CLI command / config snippet implementing the control —
// illustrative, not a copy-paste-safe runbook: adapt names, scopes and IDs to your environment.
window.TMODAAS_CATALOG = [
  {
    key: 'firewall', label: 'Firewall', layer: 'Security', inPath: true,
    vendors: {
      'Fortinet FortiGate': [
        { t: 'Enforce least-privilege firewall policies', d: 'Apply a default-deny posture on FortiGate. Remove any-to-any rules, scope policies to named address/service objects and review the rule base quarterly.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "internal-net"
        set dstaddr "web-servers"
        set service "HTTPS"
        set action accept
        set logtraffic all
    next
end` },
        { t: 'Enable IPS and web filtering profiles', d: 'Attach IPS, antivirus and web filtering security profiles to all internet-facing policies and keep FortiGuard signatures on automatic update.', iso: 'A.12.6.1', pci: '11.4', sev: 'High',
          cmd: `config firewall policy
    edit 1
        set ips-sensor "default"
        set av-profile "default"
        set webfilter-profile "default"
    next
end
config system autoupdate schedule
    set status enable
    set frequency every
end` },
        { t: 'Harden management access', d: 'Restrict admin access to trusted hosts, disable HTTP/Telnet management, enforce MFA for administrator accounts and use a dedicated management VLAN.', iso: 'A.9.4.2', pci: '8.3.1', sev: 'High',
          cmd: `config system interface
    edit "mgmt"
        set allowaccess https ssh
    next
end
config system admin
    edit "admin"
        set two-factor fortitoken
        set trusthost1 10.10.0.0 255.255.255.0
    next
end` },
        { t: 'Patch FortiOS promptly', d: 'Subscribe to Fortinet PSIRT advisories and apply firmware updates within a defined maintenance window; several FortiOS SSL-VPN CVEs are actively exploited.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `# Check current build and available upgrades
get system status
execute update-now
# Schedule via Fortinet firmware management in FortiManager for HA pairs` },
        { t: 'Centralise and retain logs', d: 'Forward traffic and event logs to FortiAnalyzer or a central syslog/SIEM and retain them for at least 12 months.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `config log syslogd setting
    set status enable
    set server "10.10.0.50"
    set port 514
    set format cef
end` },
      ],
      'Palo Alto NGFW': [
        { t: 'Use App-ID based least-privilege rules', d: 'Write security policies on App-ID rather than ports, remove overly-broad "application: any" rules and enable policy usage review.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `set rulebase security rules allow-web-app from trust to untrust \\
  source any destination any \\
  application ssl web-browsing \\
  service application-default action allow
show rule-hit-count rulebase security` },
        { t: 'Attach Threat Prevention profiles', d: 'Apply vulnerability protection, anti-spyware and antivirus profiles to all allow rules; keep content updates on a daily schedule.', iso: 'A.12.6.1', pci: '11.4', sev: 'High',
          cmd: `set rulebase security rules allow-web-app profile-setting profiles \\
  vulnerability strict spyware strict virus strict
set deviceconfig system update-schedule threats recurring daily at 02:00
set deviceconfig system update-schedule threats recurring action download-and-install` },
        { t: 'Isolate the management interface', d: 'Place the management interface on a dedicated out-of-band network, permit access only from admin subnets and enforce MFA via SAML/RADIUS.', iso: 'A.9.4.2', pci: '8.3.1', sev: 'High',
          cmd: `set deviceconfig system permitted-ip 10.10.0.0/24
set shared authentication-profile mfa-radius method radius \\
  server-profile corp-radius` },
        { t: 'Keep PAN-OS at a preferred release', d: 'Track Palo Alto security advisories and stay on a preferred/fixed PAN-OS release; validate HA pairs before and after upgrades.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `request system software check
request system software download version <preferred-release>
request system software install version <preferred-release>
show high-availability state` },
        { t: 'Enable decryption where lawful', d: 'Apply SSL forward proxy/inbound inspection on high-risk flows so threat profiles can inspect encrypted traffic; log decryption exclusions.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium',
          cmd: `set rulebase decryption rules decrypt-outbound from trust to untrust \\
  source any destination any service any \\
  action decrypt type ssl-forward-proxy` },
      ],
      'Cisco ASA/Firepower': [
        { t: 'Adopt Firepower Threat Defense policies', d: 'Migrate legacy ASA access-lists to FTD access-control policies with application/URL filtering and remove any permit-any rules.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `# FMC / FDM: Policies > Access Control > New Rule
# CLI (classic ASA, being retired):
no access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended permit tcp any object WEB-SERVERS eq 443` },
        { t: 'Enable IPS and malware protection', d: 'Apply Snort IPS and AMP for Networks policies to internet-facing access-control rules and keep the intrusion rule set on automatic update.', iso: 'A.12.6.1', pci: '11.4', sev: 'High',
          cmd: `# FMC: Objects > Intrusion Rules > Rule Update > Enable automatic updates
# Attach "Balanced Security and Connectivity" intrusion policy + AMP file policy
# to the internet-facing access control rule` },
        { t: 'Restrict ASDM/CLI management', d: 'Limit management-access to trusted hosts, disable Telnet, enforce SSH with certificate/RADIUS auth and MFA for privileged levels.', iso: 'A.9.4.2', pci: '8.3.1', sev: 'High',
          cmd: `no telnet 0.0.0.0 0.0.0.0
ssh 10.10.0.0 255.255.255.0 management
ssh version 2
aaa authentication ssh console RADIUS_MFA LOCAL` },
        { t: 'Patch ASA/FTD software promptly', d: 'Track Cisco PSIRT advisories and apply software updates within a defined window; ASA VPN CVEs have seen active mass exploitation.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `show version
# Cisco.com Software Download > apply per Cisco PSIRT advisory
# FTD: System > Updates > Upload Update > Install` },
        { t: 'Send events to a central collector', d: 'Forward syslog and Firepower eStreamer events to a SIEM/FMC and retain logs for at least 12 months.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `logging enable
logging host management 10.10.0.50
logging trap informational` },
      ],
    },
  },
  {
    key: 'loadBalancer', label: 'Load Balancer', layer: 'Infrastructure', inPath: true,
    vendors: {
      'F5 BIG-IP': [
        { t: 'Terminate TLS with a strong cipher suite', d: 'Use client-SSL profiles limited to TLS 1.2+, disable weak ciphers and renegotiation, and automate certificate rotation.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `tmsh create ltm profile client-ssl clientssl_strong { \\
  ciphers "TLSv1_2:!SSLv3:!EXPORT:!DES:!RC4" \\
  options { dont-insert-empty-fragments no-sslv2 no-sslv3 no-tlsv1 no-tlsv1_1 } \\
  renegotiation disabled }` },
        { t: 'Lock down the management plane', d: 'Restrict access to the management interface and self-IPs (port lockdown: allow none/custom), and never expose the TMUI to the internet — see CVE-2020-5902.', iso: 'A.9.4.2', pci: '1.3', sev: 'High',
          cmd: `tmsh modify net self-allow defaults { tcp:22 tcp:443 }
tmsh modify sys management-ip-rules rules add { \\
  { name allow-mgmt-net source 10.10.0.0/24 action accept } }` },
        { t: 'Deploy WAF policy on public virtual servers', d: 'Apply an ASM/Advanced WAF policy in blocking mode for internet-facing applications, tuned from a learning period.', iso: 'A.14.1.2', pci: '6.6', sev: 'High',
          cmd: `tmsh create asm policy webapp-policy defaults-from POLICY_TEMPLATE_RAPID_DEPLOYMENT
tmsh modify asm policy webapp-policy enforcement-mode blocking
tmsh modify ltm virtual vs_https profiles add { asm_auto_l7_policy webapp-policy }` },
        { t: 'Patch TMOS on a defined cadence', d: 'Track F5 quarterly security notifications and apply point releases; test on the standby unit and fail over.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `tmsh show sys version
tmsh install sys software image BIGIP-17.1.1.iso volume HD1.2
tmsh run sys failover standby` },
        { t: 'Ship logs to remote analytics', d: 'Configure high-speed logging of LTM/ASM events to a SIEM; alert on config changes and failed logins.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `tmsh create sys log-config destination remote-high-speed-log hsl_siem { \\
  pool-name siem_pool protocol tcp }
tmsh create sys log-config publisher siem_publisher { destinations add { hsl_siem } }` },
      ],
      'Citrix ADC': [
        { t: 'Remediate known ADC CVEs immediately', d: 'Citrix ADC/Gateway appliances are frequent mass-exploitation targets (e.g. CVE-2019-19781, CVE-2023-3519); apply security builds as an emergency change.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `show version
# Download the fixed build referenced in the Citrix Security Bulletin, then:
install ns <build>.tgz
reboot -warm` },
        { t: 'Replace default credentials and enforce MFA', d: 'Change the default nsroot password, integrate admin auth with LDAP/RADIUS and require MFA for management access.', iso: 'A.9.2.4', pci: '2.1', sev: 'High',
          cmd: `set system user nsroot -password <strong-password>
add authenticationRadiusAction radius-mfa -serverIP 10.10.0.60 -serverPort 1812
bind system global radius-mfa -priority 100` },
        { t: 'Restrict NSIP management access', d: 'Bind management to a dedicated subnet/VLAN, block internet access to the NSIP and disable unneeded management services.', iso: 'A.9.4.2', pci: '1.3', sev: 'High',
          cmd: `set ns ip 10.10.0.10 255.255.255.0 -mgmtAccess ENABLED -telnet DISABLED
add ns acl deny-nsip-internet DENY -destIP 10.10.0.10 -srcIP != 10.10.0.0-10.10.0.255
apply ns acls` },
        { t: 'Harden TLS profiles', d: 'Enforce TLS 1.2+ front-end and back-end profiles, disable SSLv3/weak ciphers and enable HSTS on content-switching virtual servers.', iso: 'A.10.1.1', pci: '4.1', sev: 'Medium',
          cmd: `set ssl vserver vs_https -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED -ssl3 DISABLED
set ssl vserver vs_https -hsts ENABLED -maxage 31536000 -includeSubDomains YES` },
        { t: 'Enable AppFirewall and audit logging', d: 'Use Citrix Web App Firewall profiles on exposed virtual servers and forward audit/syslog events to a central collector.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `add appfw profile waf_profile
bind lb vserver vs_https -policyName waf_policy -priority 100
add audit syslogAction siem_log 10.10.0.50 -loglevel INFORMATIONAL` },
      ],
      'AWS Elastic Load Balancing': [
        { t: 'Enforce a modern TLS security policy', d: 'Select an ELBSecurityPolicy that limits listeners to TLS 1.2+ with strong ciphers and enable ALB deletion protection on production listeners.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `aws elbv2 modify-listener --listener-arn $LISTENER_ARN \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06
aws elbv2 modify-load-balancer-attributes --load-balancer-arn $LB_ARN \\
  --attributes Key=deletion_protection.enabled,Value=true` },
        { t: 'Attach AWS WAF to internet-facing ALBs', d: 'Associate a WAFv2 web ACL with managed rule groups (SQLi, XSS, bot control) on public application load balancers.', iso: 'A.14.1.2', pci: '6.6', sev: 'High',
          cmd: `aws wafv2 associate-web-acl \\
  --web-acl-arn $WEB_ACL_ARN \\
  --resource-arn $LB_ARN` },
        { t: 'Restrict security groups to least privilege', d: 'Scope the load balancer security group to required source CIDRs/ports only and keep target-group security groups reachable solely from the LB.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `aws ec2 authorize-security-group-ingress --group-id $LB_SG \\
  --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $TARGET_SG \\
  --protocol tcp --port 8443 --source-group $LB_SG` },
        { t: 'Enable access logging to S3', d: 'Turn on ELB access logs to a dedicated, encrypted S3 bucket with lifecycle policies and query them via Athena for anomaly detection.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn $LB_ARN \\
  --attributes Key=access_logs.s3.enabled,Value=true \\
    Key=access_logs.s3.bucket,Value=tmodaas-alb-logs \\
    Key=access_logs.s3.prefix,Value=prod-lb` },
        { t: 'Automate certificate rotation with ACM', d: 'Provision listener certificates through AWS Certificate Manager for automatic renewal and avoid manually uploaded certs that can silently expire.', iso: 'A.12.6.1', pci: '4.1', sev: 'Medium',
          cmd: `aws acm request-certificate --domain-name app.example.com \\
  --validation-method DNS
aws elbv2 modify-listener --listener-arn $LISTENER_ARN \\
  --certificates CertificateArn=$ACM_CERT_ARN` },
      ],
    },
  },
  {
    key: 'hypervisor', label: 'Hypervisor / Cloud', layer: 'Infrastructure', inPath: false,
    vendors: {
      'VMware ESXi': [
        { t: 'Enable lockdown mode', d: 'Run hosts in normal or strict lockdown mode so all operations flow through vCenter, and disable the ESXi Shell and SSH except during maintenance.', iso: 'A.9.4.2', pci: '2.2.4', sev: 'High',
          cmd: `Get-VMHost | Set-VMHost -State Maintenance
Get-VMHost esxi01 | Get-VMHostService | Where {$_.Key -in "TSM","TSM-SSH"} | Stop-VMHostService -Confirm:$false
(Get-VMHost esxi01).ExtensionData.EnterLockdownMode()` },
        { t: 'Patch hosts via vLCM baselines', d: 'Apply VMware security patches through Lifecycle Manager images/baselines; ESXi ransomware campaigns target unpatched hosts.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `Get-Cluster prod-cluster | Get-VMHost | Update-Baseline -Confirm:$false
Get-Cluster prod-cluster | Test-Compliance
Get-Cluster prod-cluster | Update-Entity -Confirm:$false` },
        { t: 'Isolate management and vMotion networks', d: 'Keep management, vMotion and storage traffic on dedicated non-routable VLANs, separate from VM guest networks.', iso: 'A.13.1.3', pci: '1.3.6', sev: 'High',
          cmd: `Get-VMHost esxi01 | Get-VirtualPortGroup -Name "vMotion" | Set-VirtualPortGroup -VLanId 4090
Get-VMHost esxi01 | Get-VMHostNetworkAdapter -VMKernel | Where {$_.PortGroupName -eq "Management Network"} | \\
  Set-VMHostNetworkAdapter -VMotionEnabled:$false` },
        { t: 'Use Secure Boot and TPM attestation', d: 'Enable UEFI Secure Boot for ESXi and host attestation with TPM 2.0 so unsigned VIBs and tampered boot chains are rejected.', iso: 'A.14.2.4', pci: '11.5', sev: 'Medium',
          cmd: `esxcli system settings encryption get
# Enable Secure Boot in host BIOS, then validate:
/usr/lib/vmware/secureboot/bin/secureBoot.py -s` },
        { t: 'Forward host logs and NTP-sync', d: 'Point all hosts at a central syslog target and authoritative NTP so events are complete and correlatable.', iso: 'A.12.4.4', pci: '10.4', sev: 'Medium',
          cmd: `esxcli system syslog config set --loghost='tcp://10.10.0.50:514'
esxcli system syslog reload
esxcli system ntp set --server=10.10.0.1 --enabled=true` },
      ],
      'Microsoft Hyper-V': [
        { t: 'Run hosts on Server Core', d: 'Minimise the attack surface by installing the Hyper-V role on Server Core with no other roles or workloads on the host partition.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'High',
          cmd: `Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
# Deployed from a Server Core image (not Desktop Experience)
Get-WindowsFeature | Where InstallState -eq Installed` },
        { t: 'Use shielded VMs for sensitive workloads', d: 'Deploy a guarded fabric with Host Guardian Service; shielded VMs encrypt state and block console/PowerShell Direct access from host admins.', iso: 'A.10.1.1', pci: '3.4', sev: 'Medium',
          cmd: `Set-VMSecurity -VMName SensitiveVM -Shielded $true
Set-VMKeyProtector -VMName SensitiveVM -NewLocalKeyProtector
Enable-VMTPM -VMName SensitiveVM` },
        { t: 'Patch hosts through a managed channel', d: 'Apply monthly cumulative updates through WSUS/Azure Update Manager with cluster-aware updating for failover clusters.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `Start-CauRun -ClusterName HV-Cluster01 -CauPluginName Microsoft.WindowsUpdatePlugin
Get-CauReport -ClusterName HV-Cluster01 -Detailed` },
        { t: 'Separate the management network', d: 'Use a dedicated management VLAN and vSwitch; block VM guest networks from reaching host management endpoints.', iso: 'A.13.1.3', pci: '1.3.6', sev: 'High',
          cmd: `New-VMSwitch -Name "Mgmt-vSwitch" -NetAdapterName "NIC-Mgmt" -AllowManagementOS $true
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName "Mgmt-vSwitch" -Access -VlanId 10` },
        { t: 'Constrain admin rights with JEA', d: 'Delegate host administration through Just Enough Administration roles instead of broad local Administrators membership.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium',
          cmd: `Register-PSSessionConfiguration -Name "HyperV-Operators" \\
  -Path .\\HyperVJEA.pssc -Force
Enter-PSSession -ComputerName hv-host01 -ConfigurationName "HyperV-Operators"` },
      ],
      'Nutanix AHV': [
        { t: 'Enable cluster lockdown mode', d: 'Enforce key-based SSH only (or disable remote shell entirely) with Nutanix cluster lockdown, and change default CVM/host credentials.', iso: 'A.9.4.2', pci: '2.1', sev: 'High',
          cmd: `ncli cluster edit-cvm-security-params enable-lockdown-mode=true
ncli cluster edit-cvm-security-params enable-key-based-only-authentication=true` },
        { t: 'Keep AOS/AHV current with LCM', d: 'Use Life Cycle Manager to apply AOS, AHV and firmware security updates; review Nutanix security advisories monthly.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `# Prism Central: LCM > Inventory > Perform Inventory
# LCM > Updates > select AOS/AHV entries > Update
ncli cluster info` },
        { t: 'Enable data-at-rest encryption', d: 'Turn on cluster-level software encryption or SED drives with an external KMS to protect data on removed disks.', iso: 'A.10.1.1', pci: '3.4', sev: 'Medium',
          cmd: `ncli data-at-rest-encryption-certificate add-signed-cert \\
  cert-file=cvm.crt key-file=cvm.key ca-chain-file=ca.pem
ncli data-at-rest-encryption enable-software-encryption` },
        { t: 'Enforce Prism RBAC with MFA', d: 'Integrate Prism with AD/SAML, assign least-privilege roles and require MFA for administrative logins.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High',
          cmd: `ncli authconfig add-directory name=corp-ad domain=corp.example.com \\
  directory-url='ldap://dc01.corp.example.com' directory-type=ACTIVE_DIRECTORY
ncli role-mapping create role=CLUSTER_ADMIN entity-type=OU values=NutanixAdmins` },
        { t: 'Forward audit logs to a SIEM', d: 'Configure rsyslog forwarding for CVM and AHV audit events and alert on configuration changes.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `ncli rsyslog-config add-server name=siem ip-address=10.10.0.50 port=514 \\
  network-protocol=tcp
ncli rsyslog-config add-module name=siem module-name=AUDIT level=INFO` },
      ],
      'Microsoft Azure': [
        { t: 'Enable Microsoft Defender for Cloud', d: 'Turn on Defender plans for servers, SQL and storage; remediate recommendations to raise Secure Score on the subscription.', iso: 'A.12.6.1', pci: '11.2', sev: 'High',
          cmd: `az security pricing create --name VirtualMachines --tier Standard
az security pricing create --name SqlServers --tier Standard
az security pricing create --name StorageAccounts --tier Standard` },
        { t: 'Apply least-privilege NSGs', d: 'Restrict inbound rules on network security groups to required ports/sources only; deny direct RDP/SSH from the internet, use Bastion.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `az network nsg rule create --nsg-name web-nsg -g rg-prod \\
  --name allow-https --priority 100 --access Allow \\
  --protocol Tcp --destination-port-ranges 443
az network nsg rule delete --nsg-name web-nsg -g rg-prod --name allow-rdp-any` },
        { t: 'Require MFA and PIM for privileged roles', d: 'Enforce MFA via Conditional Access and use Privileged Identity Management for just-in-time activation of Owner/Contributor roles.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High',
          cmd: `az ad conditional-access policy create --display-name "Require MFA" \\
  --state enabled --grant-controls '{"builtInControls":["mfa"]}'
# Enable PIM eligible assignment for Owner/Contributor via Entra ID > PIM` },
        { t: 'Enforce baselines with Azure Policy', d: 'Assign the Microsoft cloud security benchmark initiative to audit/deny drift from the hardening baseline across resources.', iso: 'A.18.2.3', pci: '2.2', sev: 'Medium',
          cmd: `az policy assignment create --name mcsb-baseline \\
  --policy-set-definition "1f3afdf9-d0c9-4c3d-847f-89da613e70a8" \\
  --scope "/subscriptions/$SUB_ID"` },
        { t: 'Retain activity and resource logs', d: 'Route activity logs and diagnostics to Log Analytics with at least 12 months retention and alert on privileged operations.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `az monitor diagnostic-settings create --name activity-to-law \\
  --resource "/subscriptions/$SUB_ID" \\
  --workspace $LAW_ID --logs '[{"category":"Administrative","enabled":true}]'` },
      ],
      'Amazon Web Services (EC2)': [
        { t: 'Enable GuardDuty and Security Hub', d: 'Turn on GuardDuty threat detection and Security Hub with the AWS Foundational/CIS standards across all accounts and remediate active findings.', iso: 'A.12.6.1', pci: '11.2', sev: 'High',
          cmd: `aws guardduty create-detector --enable
aws securityhub enable-security-hub --enable-default-standards
aws securityhub batch-enable-standards --standards-subscription-requests \\
  StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0` },
        { t: 'Apply least-privilege security groups and NACLs', d: 'Scope security group ingress to required ports/sources only, deny direct SSH/RDP from 0.0.0.0/0 and use Session Manager/Systems Manager instead of bastion SSH.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `aws ec2 revoke-security-group-ingress --group-id $SG_ID \\
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ssm start-session --target $INSTANCE_ID` },
        { t: 'Enforce MFA and short-lived credentials', d: 'Require MFA for the root account and IAM users, prefer IAM roles/STS over long-lived access keys, and rotate any remaining keys regularly.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High',
          cmd: `aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa \\
  --outfile qrcode.png --bootstrap-method QRCodePNG
aws sts assume-role --role-arn $ROLE_ARN --role-session-name ops-session` },
        { t: 'Guard rail accounts with SCPs and Config', d: 'Apply Service Control Policies at the Organization level and AWS Config conformance packs so drift from the hardening baseline is detected and denied.', iso: 'A.18.2.3', pci: '2.2', sev: 'Medium',
          cmd: `aws organizations create-policy --name deny-root-actions \\
  --type SERVICE_CONTROL_POLICY --content file://scp-deny-root.json
aws configservice put-conformance-pack --conformance-pack-name cis-benchmark \\
  --template-s3-uri s3://aws-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v1.4-Level1.yaml` },
        { t: 'Centralise CloudTrail and VPC Flow Logs', d: 'Enable an organization-wide CloudTrail trail and VPC Flow Logs to a dedicated, encrypted logging account with at least 12 months retention.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `aws cloudtrail create-trail --name org-trail --s3-bucket-name tmodaas-cloudtrail \\
  --is-organization-trail --is-multi-region-trail
aws ec2 create-flow-logs --resource-type VPC --resource-ids $VPC_ID \\
  --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::tmodaas-flow-logs` },
      ],
      'Google Cloud Platform (Compute Engine)': [
        { t: 'Enable Security Command Center', d: 'Turn on Security Command Center Premium and remediate active findings (misconfigurations, vulnerabilities, active threats) across the organization.', iso: 'A.12.6.1', pci: '11.2', sev: 'High',
          cmd: `gcloud scc settings services enable --service=security-health-analytics \\
  --organization=$ORG_ID
gcloud scc findings list $ORG_ID --filter="state=\\"ACTIVE\\""` },
        { t: 'Apply least-privilege firewall rules', d: 'Scope VPC firewall rules to required tags/service accounts and ports, deny direct SSH/RDP from the internet and use Identity-Aware Proxy for admin access.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `gcloud compute firewall-rules create allow-iap-ssh \\
  --direction=INGRESS --action=allow --rules=tcp:22 \\
  --source-ranges=35.235.240.0/20
gcloud compute firewall-rules delete allow-ssh-any` },
        { t: 'Enforce MFA and least-privilege IAM', d: 'Require 2-Step Verification (or a security key) for all users, grant IAM roles at the narrowest scope and avoid primitive Owner/Editor roles on projects.', iso: 'A.9.2.3', pci: '8.3.1', sev: 'High',
          cmd: `gcloud projects remove-iam-policy-binding $PROJECT_ID \\
  --member="user:dev@example.com" --role="roles/editor"
gcloud projects add-iam-policy-binding $PROJECT_ID \\
  --member="user:dev@example.com" --role="roles/compute.instanceAdmin.v1"` },
        { t: 'Enforce Organization Policies', d: 'Apply Organization Policy constraints (e.g. restrict public IPs, require Shielded VM, disable serial port access) to keep resources on the hardening baseline.', iso: 'A.18.2.3', pci: '2.2', sev: 'Medium',
          cmd: `gcloud resource-manager org-policies enable-enforce \\
  compute.requireShieldedVm --organization=$ORG_ID
gcloud resource-manager org-policies enable-enforce \\
  compute.vmExternalIpAccess --organization=$ORG_ID` },
        { t: 'Centralise Cloud Audit and VPC Flow Logs', d: 'Enable Admin Activity/Data Access audit logs and VPC Flow Logs, export them to a dedicated logging project/SIEM with at least 12 months retention.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `gcloud compute networks subnets update prod-subnet --region=us-central1 \\
  --enable-flow-logs
gcloud logging sinks create org-siem-sink \\
  storage.googleapis.com/tmodaas-audit-logs --include-children --organization=$ORG_ID` },
      ],
    },
  },
  {
    key: 'container', label: 'Container Platform / Kubernetes', layer: 'Infrastructure', inPath: false,
    vendors: {
      'Kubernetes (self-managed)': [
        { t: 'Enforce RBAC and disable anonymous access', d: 'Apply least-privilege Role/ClusterRole bindings, disable the legacy ABAC/insecure port, and remove system:anonymous cluster-admin bindings.', iso: 'A.9.4.1', pci: '7.1.2', sev: 'High',
          cmd: `kubectl create rolebinding dev-read-only --clusterrole=view \\
  --user=dev@example.com --namespace=app
kubectl delete clusterrolebinding cluster-admin-anonymous 2>/dev/null
# kube-apiserver flags: --anonymous-auth=false --authorization-mode=RBAC` },
        { t: 'Apply Pod Security Standards', d: 'Enforce the "restricted" Pod Security Standard (or OPA/Kyverno policies) to block privileged containers, host namespace sharing and hostPath mounts.', iso: 'A.13.1.3', pci: '2.2.4', sev: 'High',
          cmd: `kubectl label namespace app \\
  pod-security.kubernetes.io/enforce=restricted \\
  pod-security.kubernetes.io/warn=restricted` },
        { t: 'Encrypt and restrict etcd', d: 'Enable encryption at rest for Secrets, restrict etcd to the control-plane network only and require mutual TLS for client access.', iso: 'A.10.1.1', pci: '3.4', sev: 'High',
          cmd: `# kube-apiserver: --encryption-provider-config=/etc/kubernetes/enc/config.yaml
# etcd: --client-cert-auth=true --peer-client-cert-auth=true
etcdctl --cert=/etc/etcd/pki/client.crt --key=/etc/etcd/pki/client.key \\
  --cacert=/etc/etcd/pki/ca.crt endpoint health` },
        { t: 'Scan images and enforce admission control', d: 'Scan container images for CVEs in the pipeline and use an admission controller to block unsigned or vulnerable images from running.', iso: 'A.12.6.1', pci: '6.3.2', sev: 'High',
          cmd: `trivy image --severity CRITICAL,HIGH --exit-code 1 registry.example.com/app:latest
kubectl apply -f kyverno-policy-verify-images.yaml` },
        { t: 'Apply network policies and audit logging', d: 'Default-deny pod-to-pod traffic with NetworkPolicies (Calico/Cilium) and enable the Kubernetes audit log forwarded to a SIEM.', iso: 'A.13.1.1', pci: '10.2', sev: 'Medium',
          cmd: `kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny, namespace: app }
spec: { podSelector: {}, policyTypes: [Ingress, Egress] }
EOF
# kube-apiserver: --audit-log-path=/var/log/kubernetes/audit.log --audit-policy-file=...` },
      ],
      'Amazon EKS': [
        { t: 'Use IRSA instead of node instance roles', d: 'Grant AWS permissions to pods via IAM Roles for Service Accounts rather than broad node IAM roles, so a compromised pod cannot assume the node’s full permissions.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'High',
          cmd: `eksctl create iamserviceaccount --cluster=prod-eks \\
  --namespace=app --name=app-sa \\
  --attach-policy-arn=arn:aws:iam::123456789012:policy/AppS3ReadOnly \\
  --approve` },
        { t: 'Restrict API server endpoint access', d: 'Disable or restrict the public EKS API endpoint to allow-listed CIDRs and prefer private endpoint access from a bastion/VPN.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `aws eks update-cluster-config --name prod-eks \\
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs="10.10.0.0/24",endpointPrivateAccess=true` },
        { t: 'Scan images with Amazon ECR/Inspector', d: 'Enable ECR image scanning and Amazon Inspector for container images, and block deployment of images with critical findings via admission policy.', iso: 'A.12.6.1', pci: '6.3.2', sev: 'High',
          cmd: `aws ecr put-image-scanning-configuration --repository-name app \\
  --image-scanning-configuration scanOnPush=true
aws inspector2 enable --resource-types ECR` },
        { t: 'Enable EKS control-plane logging', d: 'Turn on API server, audit, authenticator and scheduler logs to CloudWatch and forward to a SIEM with alerting on RBAC/API anomalies.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `aws eks update-cluster-config --name prod-eks \\
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","scheduler"],"enabled":true}]}'` },
        { t: 'Apply Pod Security Standards and network policy', d: 'Enforce the "restricted" Pod Security Standard and use Amazon VPC CNI/Calico network policies to default-deny pod-to-pod traffic.', iso: 'A.13.1.3', pci: '2.2.4', sev: 'High',
          cmd: `kubectl label namespace app pod-security.kubernetes.io/enforce=restricted
kubectl apply -f eks-calico-network-policy-default-deny.yaml` },
      ],
      'Docker Engine': [
        { t: 'Run containers as a non-root user', d: 'Set USER in Dockerfiles and run the daemon with user namespace remapping so a container escape does not yield host root.', iso: 'A.9.4.4', pci: '2.2.2', sev: 'High',
          cmd: `# Dockerfile
RUN adduser --disabled-password appuser
USER appuser
# /etc/docker/daemon.json
{ "userns-remap": "default" }` },
        { t: 'Restrict the Docker daemon socket', d: 'Never expose the Docker socket over TCP without TLS client auth, and avoid mounting /var/run/docker.sock into containers.', iso: 'A.9.4.2', pci: '1.3', sev: 'High',
          cmd: `dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem \\
  --tlskey=server-key.pem -H=0.0.0.0:2376` },
        { t: 'Scan images before deployment', d: 'Scan images with Trivy/Docker Scout in CI and pin base images to digests rather than mutable tags to prevent supply-chain drift.', iso: 'A.12.6.1', pci: '6.3.2', sev: 'High',
          cmd: `trivy image --severity CRITICAL,HIGH --exit-code 1 app:latest
docker scout cves app:latest
FROM node@sha256:9c1234...  # pin by digest, not :latest` },
        { t: 'Apply resource and capability limits', d: 'Drop unnecessary Linux capabilities (--cap-drop=ALL, add back only what is required), set memory/CPU limits and enable seccomp/AppArmor profiles.', iso: 'A.13.1.3', pci: '2.2.4', sev: 'Medium',
          cmd: `docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE \\
  --memory=512m --cpus=1 \\
  --security-opt seccomp=default.json --security-opt apparmor=docker-default \\
  app:latest` },
        { t: 'Enable and centralise daemon logging', d: 'Configure a logging driver that ships container and daemon events to a central collector, and enable Docker Content Trust for image signing.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `docker run --log-driver=syslog --log-opt syslog-address=tcp://10.10.0.50:514 app:latest
export DOCKER_CONTENT_TRUST=1
docker push registry.example.com/app:latest` },
      ],
    },
  },
  {
    key: 'operatingSystem', label: 'Operating System', layer: 'Infrastructure', inPath: false,
    vendors: {
      'Windows Server': [
        { t: 'Apply a CIS/STIG hardening baseline', d: 'Deploy CIS Benchmark or Microsoft security baseline GPOs and monitor drift with a configuration-compliance tool.', iso: 'A.12.5.1', pci: '2.2', sev: 'High',
          cmd: `Import-Module LGPO
LGPO.exe /g "C:\\Baselines\\WindowsServer2022-CIS"
Invoke-DscResource -Name AuditPolicySubcategory -ModuleName AuditPolicyDsc -Method Test` },
        { t: 'Patch monthly with defined SLAs', d: 'Deploy cumulative updates through WSUS/Intune within 30 days (7 days for critical, internet-facing systems).', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Get-WUHistory | Select-Object -First 10
# WSUS: approve Critical/Security updates in the "Critical - 7 day" ring` },
        { t: 'Randomise local admin passwords with LAPS', d: 'Use Windows LAPS so every server has a unique, rotated local administrator password stored in AD/Entra.', iso: 'A.9.2.4', pci: '8.2.6', sev: 'High',
          cmd: `Install-WindowsFeature -Name RSAT-AD-PowerShell
Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=corp,DC=example,DC=com"
Get-LapsADPassword -Identity SRV01 -AsPlainText` },
        { t: 'Disable legacy protocols', d: 'Remove SMBv1, disable NTLMv1 and LLMNR/NetBIOS name resolution, and enforce SMB signing.', iso: 'A.13.1.2', pci: '2.2.3', sev: 'Medium',
          cmd: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" \\
  -Name EnableMulticast -Value 0` },
        { t: 'Enable EDR and audit forwarding', d: 'Run Defender for Endpoint (or equivalent EDR) and forward Security event logs to a SIEM with alerting on privilege changes.', iso: 'A.12.4.1', pci: '10.6', sev: 'High',
          cmd: `Set-MpPreference -DisableRealtimeMonitoring $false
wecutil qc /q
wevtutil sl Security /e:true` },
      ],
      'Linux': [
        { t: 'Harden to the CIS benchmark', d: 'Apply the distribution CIS benchmark (partition options, sysctl, service removal) and verify with OpenSCAP or Lynis.', iso: 'A.12.5.1', pci: '2.2', sev: 'High',
          cmd: `oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \\
  --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
lynis audit system` },
        { t: 'Keep SELinux/AppArmor enforcing', d: 'Run mandatory access control in enforcing mode; never disable it to "fix" application issues — write targeted policies instead.', iso: 'A.9.4.1', pci: '2.2.5', sev: 'Medium',
          cmd: `setenforce 1
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
aa-status   # AppArmor equivalent on Debian/Ubuntu` },
        { t: 'Restrict SSH access', d: 'Permit key-based authentication only, disable root login, and gate SSH behind a bastion or allow-listed subnets.', iso: 'A.9.4.2', pci: '8.2', sev: 'High',
          cmd: `sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl reload sshd` },
        { t: 'Automate security updates', d: 'Enable unattended security upgrades (or a patch pipeline) so kernel and package CVEs are closed within SLA.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `apt install unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
# RHEL/CentOS: dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer` },
        { t: 'Enable auditd and central logging', d: 'Audit privileged commands and identity changes with auditd rules and forward journals/syslog to a central collector.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `auditctl -w /etc/passwd -p wa -k identity
auditctl -a always,exit -F arch=b64 -F euid=0 -S execve -k root-exec
echo "*.* @@10.10.0.50:514" >> /etc/rsyslog.conf && systemctl restart rsyslog` },
      ],
    },
  },
  {
    key: 'serverless', label: 'Serverless / PaaS', layer: 'Application', inPath: true,
    vendors: {
      'AWS Lambda': [
        { t: 'Grant least-privilege execution roles', d: 'Scope each function’s IAM execution role to the specific resources/actions it needs; never reuse a broad shared role across unrelated functions.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'High',
          cmd: `aws iam create-policy --policy-name fn-orders-policy \\
  --policy-document file://fn-orders-least-priv.json
aws lambda update-function-configuration --function-name orders-fn \\
  --role arn:aws:iam::123456789012:role/fn-orders-role` },
        { t: 'Keep runtimes and dependencies patched', d: 'Track deprecated/EOL Lambda runtimes, rebuild on the latest supported runtime and scan layers and dependencies for known CVEs in the pipeline.', iso: 'A.12.6.1', pci: '6.3.2', sev: 'High',
          cmd: `aws lambda update-function-configuration --function-name orders-fn --runtime nodejs20.x
npm audit --audit-level=high
trivy fs --severity CRITICAL,HIGH .` },
        { t: 'Validate all inputs and encrypt environment variables', d: 'Treat event payloads (API Gateway, S3, SQS) as untrusted input, and encrypt sensitive environment variables with a customer-managed KMS key.', iso: 'A.14.2.5', pci: '6.5', sev: 'High',
          cmd: `aws lambda update-function-configuration --function-name orders-fn \\
  --kms-key-arn arn:aws:kms:eu-west-1:123456789012:key/abcd-1234 \\
  --environment "Variables={DB_SECRET_ARN=$SECRET_ARN}"` },
        { t: 'Restrict function URLs and resource policies', d: 'Avoid public Function URLs/API Gateway routes without authorization, and scope resource-based policies to specific principals rather than "*".', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `aws lambda create-function-url-config --function-name orders-fn --auth-type AWS_IAM
aws lambda remove-permission --function-name orders-fn --statement-id public-invoke` },
        { t: 'Enable structured logging and tracing', d: 'Ship function logs to CloudWatch/a SIEM with structured JSON and enable X-Ray tracing to detect anomalous invocation patterns.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `aws lambda update-function-configuration --function-name orders-fn \\
  --tracing-config Mode=Active
aws logs put-subscription-filter --log-group-name /aws/lambda/orders-fn \\
  --filter-name to-siem --filter-pattern "" --destination-arn $FIREHOSE_ARN` },
      ],
      'Azure App Service / Functions': [
        { t: 'Use managed identities instead of secrets', d: 'Authenticate to Azure resources with system/user-assigned managed identities rather than connection strings or keys embedded in app settings.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'High',
          cmd: `az webapp identity assign --name orders-app --resource-group rg-prod
az role assignment create --assignee $PRINCIPAL_ID \\
  --role "Storage Blob Data Reader" --scope $STORAGE_ID` },
        { t: 'Restrict inbound access with access restrictions', d: 'Configure App Service access restrictions or Private Endpoints so the app is reachable only from expected networks (e.g. behind Front Door/APIM).', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `az webapp config access-restriction add --name orders-app -g rg-prod \\
  --rule-name allow-frontdoor --priority 100 \\
  --service-tag AzureFrontDoor.Backend` },
        { t: 'Enforce HTTPS and modern TLS', d: 'Enable "HTTPS Only", set the minimum TLS version to 1.2+, and disable FTP/basic auth deployment credentials.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `az webapp update --name orders-app -g rg-prod --https-only true
az webapp config set --name orders-app -g rg-prod --min-tls-version 1.2 --ftps-state Disabled` },
        { t: 'Store secrets in Key Vault', d: 'Reference Key Vault secrets via app setting references instead of storing API keys/connection strings in plaintext configuration.', iso: 'A.10.1.2', pci: '3.5', sev: 'High',
          cmd: `az keyvault secret set --vault-name kv-prod --name db-connstr --value "$CONN_STR"
az webapp config appsettings set --name orders-app -g rg-prod \\
  --settings DB_CONNSTR="@Microsoft.KeyVault(SecretUri=https://kv-prod.vault.azure.net/secrets/db-connstr/)"` },
        { t: 'Enable diagnostic logging and Defender for App Service', d: 'Turn on App Service diagnostic logs to Log Analytics and enable Microsoft Defender for App Service to detect anomalous activity.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `az monitor diagnostic-settings create --name app-to-law \\
  --resource $APP_ID --workspace $LAW_ID --logs '[{"category":"AppServiceHTTPLogs","enabled":true}]'
az security pricing create --name AppServices --tier Standard` },
      ],
      'Google Cloud Run / App Engine': [
        { t: 'Run services with a dedicated least-privilege service account', d: 'Assign each service its own service account scoped to only the APIs/resources it calls, instead of the default Compute Engine service account.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'High',
          cmd: `gcloud iam service-accounts create orders-run-sa
gcloud run deploy orders-svc --service-account=orders-run-sa@$PROJECT_ID.iam.gserviceaccount.com` },
        { t: 'Require authentication on internal services', d: 'Remove "allow unauthenticated" on services that are not meant to be public and use IAM invoker roles or Identity-Aware Proxy for internal callers.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `gcloud run services remove-iam-policy-binding orders-svc \\
  --member="allUsers" --role="roles/run.invoker"
gcloud run services add-iam-policy-binding orders-svc \\
  --member="serviceAccount:caller-sa@$PROJECT_ID.iam.gserviceaccount.com" --role="roles/run.invoker"` },
        { t: 'Pin and scan container images', d: 'Deploy images by digest rather than mutable tag, scan them with Artifact Registry vulnerability scanning, and enforce Binary Authorization for production.', iso: 'A.12.6.1', pci: '6.3.2', sev: 'High',
          cmd: `gcloud run deploy orders-svc \\
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/app/orders@sha256:9c1234...
gcloud container binauthz policy import policy.yaml` },
        { t: 'Store secrets in Secret Manager', d: 'Mount configuration secrets from Secret Manager rather than baking them into images or environment variables in plaintext.', iso: 'A.10.1.2', pci: '3.5', sev: 'High',
          cmd: `gcloud secrets create db-connstr --data-file=connstr.txt
gcloud run deploy orders-svc --set-secrets=DB_CONNSTR=db-connstr:latest` },
        { t: 'Enable Cloud Audit and request logging', d: 'Enable Admin Activity/Data Access audit logs and Cloud Run request logs, exported to a SIEM with alerting on IAM/policy changes.', iso: 'A.12.4.1', pci: '10.5.1', sev: 'Medium',
          cmd: `gcloud logging sinks create run-siem-sink storage.googleapis.com/tmodaas-run-logs \\
  --log-filter='resource.type="cloud_run_revision"'` },
      ],
    },
  },
  {
    key: 'web', label: 'Web Server', layer: 'Application', inPath: true,
    vendors: {
      'Apache HTTP Server': [
        { t: 'Suppress version disclosure', d: 'Set ServerTokens Prod and ServerSignature Off so httpd version and modules are not leaked in headers and error pages.', iso: 'A.12.5.1', pci: '2.2.4', sev: 'Medium',
          cmd: `# /etc/httpd/conf/httpd.conf
ServerTokens Prod
ServerSignature Off
systemctl reload httpd` },
        { t: 'Enforce modern TLS', d: 'Allow TLS 1.2+ only with a curated cipher list, enable HSTS and redirect all HTTP to HTTPS.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `# ssl.conf
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
RewriteEngine On
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]` },
        { t: 'Deploy ModSecurity with OWASP CRS', d: 'Run mod_security with the OWASP Core Rule Set in blocking mode to mitigate injection and common web attacks.', iso: 'A.14.1.2', pci: '6.6', sev: 'High',
          cmd: `apt install libapache2-mod-security2
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
a2enmod security2 && systemctl reload apache2` },
        { t: 'Run with least privilege', d: 'Run workers as a dedicated non-root user, disable directory indexing and unused modules (autoindex, status, cgi).', iso: 'A.9.4.4', pci: '2.2.2', sev: 'Medium',
          cmd: `# httpd.conf
User apache
Group apache
Options -Indexes
a2dismod autoindex status cgid` },
        { t: 'Patch httpd and centralise access logs', d: 'Track Apache security releases, patch within SLA and forward access/error logs for anomaly detection.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `apt update && apt upgrade apache2
# rsyslog forwarding
echo 'local1.* @@10.10.0.50:514' >> /etc/rsyslog.conf
CustomLog "|/usr/bin/logger -p local1.info" combined` },
      ],
      'Microsoft IIS': [
        { t: 'Remove unused modules and handlers', d: 'Uninstall features not required by the application (WebDAV, CGI, FTP) and remove sample/default sites.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'Medium',
          cmd: `Uninstall-WindowsFeature -Name Web-DAV-Publishing, Web-CGI, Web-FTP-Server
Remove-Website -Name "Default Web Site"` },
        { t: 'Enforce TLS 1.2+ via Schannel', d: 'Disable SSL 3.0/TLS 1.0/1.1 and weak ciphers at the Schannel level; enable HSTS on production bindings.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force
Set-ItemProperty -Path 'HKLM:\\...\\TLS 1.0\\Server' -Name Enabled -Value 0
Set-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders \\
  -Name '.' -Value @{name='Strict-Transport-Security';value='max-age=31536000'}` },
        { t: 'Configure request filtering', d: 'Set maxAllowedContentLength, block double-escaping and high-bit characters, and filter dangerous verbs and file extensions.', iso: 'A.14.1.2', pci: '6.5', sev: 'Medium',
          cmd: `Set-WebConfiguration -Filter /system.webServer/security/requestFiltering/requestLimits \\
  -Value @{maxAllowedContentLength=10485760}
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering \\
  -Name allowDoubleEscaping -Value $false` },
        { t: 'Isolate application pools', d: 'Run each site in its own app pool under a virtual/least-privilege identity so one compromised app cannot read another\u2019s content.', iso: 'A.9.4.4', pci: '2.2.1', sev: 'High',
          cmd: `New-WebAppPool -Name "orders-pool"
Set-ItemProperty IIS:\\AppPools\\orders-pool -Name processModel.identityType -Value ApplicationPoolIdentity
Set-ItemProperty IIS:\\Sites\\orders-site -Name applicationPool -Value orders-pool` },
        { t: 'Enable enhanced logging and patching', d: 'Log with W3C extended fields including X-Forwarded-For, forward to a SIEM, and patch IIS/ASP.NET via monthly Windows updates.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `Set-WebConfiguration -Filter /system.applicationHost/sites/siteDefaults/logFile \\
  -Value @{logExtFileFlags='Date,Time,ClientIP,UserName,Method,UriStem,HttpStatus,Referer'}
Get-WindowsUpdate -AcceptAll -Install` },
      ],
      'Nginx': [
        { t: 'Hide server tokens', d: 'Set server_tokens off and remove identifying headers so version details are not exposed to scanners.', iso: 'A.12.5.1', pci: '2.2.4', sev: 'Medium',
          cmd: `# /etc/nginx/nginx.conf
http { server_tokens off; more_clear_headers Server; }
nginx -s reload` },
        { t: 'Harden TLS configuration', d: 'Serve TLS 1.2/1.3 only with modern ciphers, OCSP stapling and HSTS; automate certificate renewal.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_stapling on;
add_header Strict-Transport-Security "max-age=31536000" always;
certbot renew --quiet --deploy-hook "nginx -s reload"` },
        { t: 'Apply rate limiting', d: 'Use limit_req/limit_conn zones on login and API endpoints to blunt brute-force and application-layer DoS.', iso: 'A.13.1.2', pci: '6.5', sev: 'Medium',
          cmd: `limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /login {
    limit_req zone=login burst=10 nodelay;
}` },
        { t: 'Run workers as non-root', d: 'Drop worker privileges to a dedicated user, disable autoindex and restrict access to hidden/dot files.', iso: 'A.9.4.4', pci: '2.2.2', sev: 'Medium',
          cmd: `# nginx.conf
user nginx;
autoindex off;
location ~ /\\. { deny all; }` },
        { t: 'Track security releases and add WAF', d: 'Patch nginx security releases within SLA and front public apps with ModSecurity/NAXSI or a cloud WAF.', iso: 'A.12.6.1', pci: '6.6', sev: 'High',
          cmd: `apt update && apt upgrade nginx
apt install libnginx-mod-http-modsecurity
# nginx.conf: modsecurity on; modsecurity_rules_file /etc/nginx/modsec/main.conf;` },
      ],
    },
  },
  {
    key: 'middleware', label: 'Middleware', layer: 'Application', inPath: true,
    vendors: {
      'Oracle WebLogic': [
        { t: 'Apply quarterly Critical Patch Updates', d: 'WebLogic is a recurring target for RCE exploits (T3/IIOP deserialisation); apply Oracle CPUs the quarter they are released.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `$ORACLE_HOME/OPatch/opatch apply /patches/CPUJul2024/33xxxxxx
$ORACLE_HOME/OPatch/opatch lsinventory` },
        { t: 'Block T3/IIOP from untrusted networks', d: 'Filter or disable the T3, T3S and IIOP protocols at the network edge; expose only HTTPS through the web tier.', iso: 'A.13.1.1', pci: '1.3', sev: 'High',
          cmd: `# WLST
connect('weblogic','password','t3://localhost:7001')
edit(); startEdit()
cmo.setT3ProtocolActionAllowed(false)
save(); activate()` },
        { t: 'Restrict the administration console', d: 'Bind the admin console/port to a management network, rename the default weblogic account and enforce strong admin credentials.', iso: 'A.9.4.2', pci: '8.2', sev: 'High',
          cmd: `# WLST
cmo.setListenAddress('10.10.0.20')
cd('/Security/mydomain/User/weblogic')
cmo.setName('wladmin_ops')` },
        { t: 'Encrypt tier-to-tier traffic', d: 'Enable TLS between the web tier, WebLogic and the database, including JDBC over TLS, with production-mode SSL enforcement.', iso: 'A.10.1.1', pci: '4.1', sev: 'Medium',
          cmd: `cmo.setSSLListenPort(7002)
cmo.setSSLEnabled(true)
# JDBC URL: jdbc:oracle:thin:@(DESCRIPTION=...)(SECURITY=(SSL_SERVER_CERT_DN="..."))` },
        { t: 'Run with least-privilege service accounts', d: 'Run managed servers under dedicated OS accounts with no interactive login and enable WebLogic auditing to a central log.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium',
          cmd: `useradd -r -s /sbin/nologin weblogic-svc
chown -R weblogic-svc:weblogic-svc $DOMAIN_HOME
cmo.setAuditFileSeverity('WARNING')` },
      ],
      'IBM WebSphere': [
        { t: 'Apply Interim/Fix Pack updates promptly', d: 'Track IBM security bulletins for WebSphere Application Server and apply interim fixes and fix packs within a defined SLA.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `./imcl listAvailableFixes -installationDirectory /opt/IBM/WebSphere/AppServer
./imcl install com.ibm.websphere.ND.v90.fix -repositories /fixes -acceptLicense` },
        { t: 'Enable Administrative Security and SSL', d: 'Turn on global security with LTPA/SSL for the admin console and inter-node communication; never run with security disabled.', iso: 'A.9.4.2', pci: '8.2', sev: 'High',
          cmd: `wsadmin.sh -lang jython -c \\
  "AdminTask.setGlobalSecurity('[-enabled true -enforceJava2Security true]')"
$AdminConfig save` },
        { t: 'Restrict the admin console and SOAP connector', d: 'Bind the WC_adminhost and SOAP connector ports to a management network and require MFA for console logins.', iso: 'A.13.1.1', pci: '1.3', sev: 'High',
          cmd: `wsadmin.sh -c "AdminTask.modifyServerPort('server1', \\
  '[-endPointName WC_adminhost -host 10.10.0.20]')"` },
        { t: 'Harden the default application and samples', d: 'Remove default/sample applications (snoop, hitcount) and disable directory browsing on the embedded HTTP transport.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'Medium',
          cmd: `wsadmin.sh -c "AdminApp.uninstall('DefaultApplication')"
wsadmin.sh -c "AdminApp.uninstall('SamplesGallery')"` },
        { t: 'Enable audit logging to a SIEM', d: 'Turn on WebSphere security auditing for authentication and authorization events and forward logs centrally.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `wsadmin.sh -c "AdminTask.enableSecurityAuditing('[-enable true]')"
# Configure a Generic JMS/Syslog audit event factory pointed at 10.10.0.50:514` },
      ],
      'Apache Tomcat': [
        { t: 'Remove default apps and disable directory listing', d: 'Delete the manager, host-manager, examples and docs webapps from production and set listings="false" in web.xml.', iso: 'A.12.5.1', pci: '2.2.2', sev: 'Medium',
          cmd: `rm -rf $CATALINA_HOME/webapps/{examples,docs,host-manager}
sed -i 's/<param-value>true<\\/param-value>/<param-value>false<\\/param-value>/' \\
  $CATALINA_HOME/conf/web.xml   # listings param` },
        { t: 'Harden the Manager/Host Manager apps', d: 'If retained, restrict access by IP with a RemoteAddrValve, require strong roles in tomcat-users.xml and enable MFA at the front proxy.', iso: 'A.9.4.2', pci: '8.2', sev: 'High',
          cmd: `<Valve className="org.apache.catalina.valves.RemoteAddrValve"
       allow="10\\.10\\.0\\.\\d+" />
<!-- context.xml for /manager -->` },
        { t: 'Run behind a hardened front-end with TLS', d: 'Terminate TLS 1.2+ at Apache/Nginx or the Tomcat connector, enable HSTS and set secure/HttpOnly on the session cookie.', iso: 'A.10.1.1', pci: '4.1', sev: 'High',
          cmd: `<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
    SSLEnabled="true" sslProtocol="TLS" sslEnabledProtocols="TLSv1.2,TLSv1.3" />
<Context sessionCookieName="JSESSIONID" useHttpOnly="true"><CookieProcessor sameSiteCookies="strict"/></Context>` },
        { t: 'Patch Tomcat on a defined cadence', d: 'Track Tomcat security advisories (e.g. Ghostcat, AJP-related CVEs) and apply point releases promptly; disable the AJP connector if unused.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `# Comment out or remove the AJP connector in server.xml if unused
<!-- <Connector protocol="AJP/1.3" port="8009" ... /> -->
# Download and swap in the latest patched Tomcat release per catalina.apache.org security notices` },
        { t: 'Run the service account with least privilege', d: 'Run Tomcat as a dedicated non-root user with a read-only webapps directory and enable access log valves shipped to a SIEM.', iso: 'A.9.4.4', pci: '2.2.2', sev: 'Medium',
          cmd: `useradd -r -s /sbin/nologin tomcat
chown -R tomcat:tomcat $CATALINA_HOME
chmod -R 750 $CATALINA_HOME/webapps
<Valve className="org.apache.catalina.valves.AccessLogValve"
       directory="logs" prefix="access_log" pattern="combined" />` },
      ],
    },
  },
  {
    key: 'database', label: 'Database', layer: 'Application', inPath: true,
    vendors: {
      'Oracle Database': [
        { t: 'Apply quarterly CPU patches', d: 'Track Oracle Critical Patch Updates and apply database security patches within the quarter, including OJVM components.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `$ORACLE_HOME/OPatch/opatch apply /patches/CPUJul2024/DB
$ORACLE_HOME/OPatch/opatch apply /patches/CPUJul2024/OJVM` },
        { t: 'Encrypt data with TDE', d: 'Enable Transparent Data Encryption for tablespaces holding sensitive data and manage keys in an external keystore.', iso: 'A.10.1.1', pci: '3.4', sev: 'High',
          cmd: `ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "wallet_pwd";
CREATE TABLESPACE sensitive_data
  DATAFILE '/u01/oradata/sensitive01.dbf' SIZE 100M
  ENCRYPTION USING 'AES256' DEFAULT STORAGE(ENCRYPT);` },
        { t: 'Lock down default accounts', d: 'Lock and expire unused default schemas, enforce password profiles with complexity and failed-login limits.', iso: 'A.9.2.4', pci: '2.1', sev: 'High',
          cmd: `ALTER USER scott ACCOUNT LOCK PASSWORD EXPIRE;
CREATE PROFILE app_profile LIMIT
  FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LIFE_TIME 90 PASSWORD_VERIFY_FUNCTION ora12c_verify_function;` },
        { t: 'Enable unified auditing', d: 'Audit privileged actions, logons and schema changes with Unified Auditing and forward records to a SIEM.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `CREATE AUDIT POLICY priv_ops_policy
  ACTIONS ALTER USER, DROP TABLE, CREATE USER;
AUDIT POLICY priv_ops_policy;` },
        { t: 'Encrypt client-database traffic', d: 'Enforce native network encryption or TLS for all client and application connections to the listener.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium',
          cmd: `# sqlnet.ora
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED` },
      ],
      'Microsoft SQL Server': [
        { t: 'Patch with latest CU/GDR', d: 'Apply SQL Server cumulative updates and security GDRs on a defined cadence; unsupported versions must be upgraded.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `Setup.exe /Action=Patch /IAcceptSQLServerLicenseTerms /Quiet
SELECT @@VERSION;` },
        { t: 'Enable TDE and backup encryption', d: 'Turn on Transparent Data Encryption for databases with sensitive data and encrypt backups with a protected certificate.', iso: 'A.10.1.1', pci: '3.4', sev: 'High',
          cmd: `CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<strong-password>';
CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE TDECert;
ALTER DATABASE AppDb SET ENCRYPTION ON;` },
        { t: 'Disable or rename the sa account', d: 'Prefer Windows/Entra authentication, disable mixed mode where possible and disable or rename sa with a strong password.', iso: 'A.9.2.4', pci: '2.1', sev: 'High',
          cmd: `ALTER LOGIN sa DISABLE;
ALTER LOGIN sa WITH NAME = renamed_sa_x9f2;` },
        { t: 'Force encrypted connections', d: 'Configure the instance to require TLS 1.2+ for client connections with a CA-issued certificate.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium',
          cmd: `# SQL Server Configuration Manager > Protocols > Force Encryption = Yes
# Bind CA-issued certificate under Network Configuration > Certificate` },
        { t: 'Enable SQL Audit', d: 'Audit logins, permission changes and access to sensitive objects with server/database audit specifications shipped to a SIEM.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `CREATE SERVER AUDIT SecurityAudit TO FILE (FILEPATH = 'D:\\Audit\\');
CREATE SERVER AUDIT SPECIFICATION SecAuditSpec FOR SERVER AUDIT SecurityAudit
  ADD (FAILED_LOGIN_GROUP), ADD (SERVER_PRINCIPAL_CHANGE_GROUP);
ALTER SERVER AUDIT SecurityAudit WITH (STATE = ON);` },
      ],
      'PostgreSQL': [
        { t: 'Stay on patched minor releases', d: 'Apply PostgreSQL minor version updates promptly — they are drop-in and carry the security fixes for supported majors.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `apt update && apt install --only-upgrade postgresql-16
SELECT version();` },
        { t: 'Use SCRAM-SHA-256 authentication', d: 'Set password_encryption to scram-sha-256 and migrate any md5 credentials; never use trust auth beyond local dev.', iso: 'A.9.4.2', pci: '8.2.1', sev: 'High',
          cmd: `ALTER SYSTEM SET password_encryption = 'scram-sha-256';
ALTER USER app_user WITH PASSWORD '<strong-password>';
SELECT pg_reload_conf();` },
        { t: 'Tighten pg_hba.conf', d: 'Scope host entries to specific databases, roles and CIDR ranges; require TLS (hostssl) for remote connections.', iso: 'A.13.1.1', pci: '1.2.1', sev: 'High',
          cmd: `# pg_hba.conf
hostssl appdb    app_user    10.10.0.0/24    scram-sha-256
# remove: host all all 0.0.0.0/0 trust
pg_ctl reload` },
        { t: 'Apply role-based least privilege', d: 'Grant privileges through roles, revoke default PUBLIC schema rights and separate application, migration and admin roles.', iso: 'A.9.2.3', pci: '7.1.2', sev: 'Medium',
          cmd: `REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE ROLE app_read; GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_read;
GRANT app_read TO app_user;` },
        { t: 'Log with pgAudit', d: 'Enable pgaudit for DDL and role changes, log connections and forward logs to central analysis.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `ALTER SYSTEM SET shared_preload_libraries = 'pgaudit';
ALTER SYSTEM SET pgaudit.log = 'ddl, role';
ALTER SYSTEM SET log_connections = on;` },
      ],
      'MySQL / MariaDB': [
        { t: 'Stay on patched maintenance releases', d: 'Apply MySQL/MariaDB security releases promptly; several server CVEs have affected the InnoDB and replication components.', iso: 'A.12.6.1', pci: '6.2', sev: 'High',
          cmd: `apt update && apt install --only-upgrade mysql-server
SELECT VERSION();` },
        { t: 'Remove anonymous accounts and test databases', d: 'Run mysql_secure_installation equivalents: drop anonymous users, the test database and require a password for all accounts including root.', iso: 'A.9.2.4', pci: '2.1', sev: 'High',
          cmd: `mysql_secure_installation
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;` },
        { t: 'Require TLS for client connections', d: 'Set require_secure_transport (or REQUIRE SSL per user) and issue certificates so replication and client traffic are encrypted in transit.', iso: 'A.13.2.3', pci: '4.1', sev: 'Medium',
          cmd: `SET GLOBAL require_secure_transport = ON;
ALTER USER 'app_user'@'%' REQUIRE SSL;` },
        { t: 'Enable encryption at rest', d: 'Turn on InnoDB tablespace encryption (or MariaDB data-at-rest encryption) with keys managed by an external keyring/KMS.', iso: 'A.10.1.1', pci: '3.4', sev: 'High',
          cmd: `# my.cnf
early-plugin-load=keyring_file.so
innodb_encrypt_tables=ON
ALTER TABLE app.orders ENCRYPTION='Y';` },
        { t: 'Enable the audit log plugin', d: 'Use the MySQL Enterprise/MariaDB audit plugin to log connections, queries and privilege changes, forwarded to a SIEM.', iso: 'A.12.4.1', pci: '10.2', sev: 'Medium',
          cmd: `INSTALL PLUGIN audit_log SONAME 'audit_log.so';
SET GLOBAL audit_log_policy = 'ALL';` },
      ],
    },
  },
];
