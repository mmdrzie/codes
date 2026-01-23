# PCI DSS 4.0 Compliance Checklist

## Overview
This document maps the application's security controls to the Payment Card Industry Data Security Standard (PCI DSS) version 4.0 requirements. Each requirement includes evidence of compliance and any identified gaps with remediation plans.

## Compliance Status
- **Assessment Date:** January 2026
- **Application Scope:** Web Application, API Services, Database Systems
- **Compliance Status:** In Progress
- **Next Assessment:** July 2026

---

## PCI DSS Requirements Mapping

### Requirement 1: Install and maintain a firewall configuration to protect cardholder data

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-001 | Firewall configuration for all system components | Compliant | AWS Security Groups configured per principle of least privilege | None | N/A |
| PCI-002 | Current network diagram with firewalls | Compliant | Network diagram maintained in AWS VPC console | None | N/A |
| PCI-003 | Documented firewall change process | Compliant | Change management process documented in ops manual | None | N/A |
| PCI-004 | Annual firewall rule review | Planned | Scheduled quarterly reviews via automated tooling | Not implemented | Automation tool to be deployed Q2 2026 |

### Requirement 2: Do not use vendor-supplied defaults for system passwords and other security parameters

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-005 | Default passwords changed on all devices | Compliant | Automated deployment scripts ensure unique passwords | None | N/A |
| PCI-006 | Default accounts disabled or removed | Compliant | CI/CD pipeline removes default accounts | None | N/A |
| PCI-007 | System security parameters customized | Compliant | Customized security baselines applied via Terraform | None | N/A |

### Requirement 3: Protect stored cardholder data

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-008 | Cardholder data protection methodology defined | Compliant | Data classification policy defines protection levels | None | N/A |
| PCI-009 | Sensitive authentication data not stored after authorization | Compliant | Code review confirms PAN truncated, CVV not stored | None | N/A |
| PCI-010 | Data retention policy implemented | Compliant | Automated data lifecycle management in place | None | N/A |
| PCI-011 | Strong cryptography for stored cardholder data | Compliant | AES-256 encryption for card data at rest | None | N/A |

### Requirement 4: Encrypt transmission of cardholder data across open, public networks

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-012 | TLS 1.3 enforced for all external connections | Compliant | TLS 1.3 required for all HTTPS endpoints | None | N/A |
| PCI-013 | Certificate management process | Compliant | Automated certificate renewal via ACM | None | N/A |
| PCI-014 | Secure protocols only (no SSL/early TLS) | Compliant | SSL and TLS 1.0/1.1 explicitly disabled | None | N/A |

### Requirement 5: Protect all systems against malware

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-015 | Malware protection on all systems | Compliant | Amazon Inspector runs continuously on EC2 instances | None | N/A |
| PCI-016 | Malware definitions updated | Compliant | Automated updates via AWS Systems Manager | None | N/A |
| PCI-017 | Periodic malware scans | Compliant | Weekly deep scans scheduled automatically | None | N/A |

### Requirement 6: Develop and maintain secure systems and applications

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-018 | Secure coding practices followed | Compliant | SAST tools integrated in CI/CD pipeline | None | N/A |
| PCI-019 | Code reviews conducted | Compliant | Mandatory peer reviews for all code changes | None | N/A |
| PCI-020 | Security patches applied | Compliant | Automated patching via Systems Manager | None | N/A |
| PCI-021 | Vulnerability assessments performed | Compliant | OWASP ZAP scans in CI/CD pipeline | None | N/A |

### Requirement 7: Restrict access to cardholder data by business need-to-know

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-022 | Access control policies defined | Compliant | Role-based access control (RBAC) implemented | None | N/A |
| PCI-023 | User access provisioning process | Compliant | Automated provisioning via AWS IAM | None | N/A |
| PCI-024 | Periodic access reviews | Compliant | Monthly access reviews automated via scripts | None | N/A |

### Requirement 8: Identify and authenticate access to system components

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-025 | Unique user identification | Compliant | Individual user accounts required, no shared accounts | None | N/A |
| PCI-026 | Strong authentication for all users | Compliant | MFA required for all administrative access | None | N/A |
| PCI-027 | Password complexity requirements | Compliant | 12-character minimum, complexity rules enforced | None | N/A |
| PCI-028 | Account disabling after 90 days inactivity | Compliant | Automated account disablement policy | None | N/A |

### Requirement 9: Restrict physical access to cardholder data

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-029 | Physical access controls for data center | Compliant | AWS physical security (cloud environment) | None | N/A |
| PCI-030 | Visitor control processes | Compliant | No physical access required (cloud only) | None | N/A |

### Requirement 10: Track and monitor all access to network resources and cardholder data

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-031 | Log all access to cardholder data | Compliant | CloudTrail logs all API calls, application logs | None | N/A |
| PCI-032 | Log aggregation and analysis | Compliant | Centralized logging via CloudWatch and ELK stack | None | N/A |
| PCI-033 | Clock synchronization | Compliant | NTP synchronization across all systems | None | N/A |
| PCI-034 | Log retention (1 year) | Compliant | CloudWatch logs retained for 7 years | None | N/A |

### Requirement 11: Regularly test security of network systems and processes

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-035 | Internal vulnerability scans | Compliant | Weekly automated vulnerability scans | None | N/A |
| PCI-036 | External vulnerability scans | Compliant | Monthly third-party scans | None | N/A |
| PCI-037 | Penetration testing annually | Planned | Scheduled quarterly penetration tests | Gap | Contract with external firm Q2 2026 |
| PCI-038 | Process for addressing vulnerabilities | Compliant | Vulnerability management process documented | None | N/A |

### Requirement 12: Support information security with organizational policies and programs

| Control ID | Requirement | Status | Evidence | Gap/Risk | Remediation |
|------------|-------------|---------|----------|----------|-------------|
| PCI-039 | Information security policy | Compliant | Security policy documented and distributed | None | N/A |
| PCI-040 | Annual security awareness training | Compliant | Training completed by all staff | None | N/A |
| PCI-041 | Access control policy | Compliant | Access control policy documented and enforced | None | N/A |
| PCI-042 | Incident response plan | Compliant | Incident response plan documented and tested | None | N/A |

---

## Compliance Evidence Repository

### Security Assessments
- [ ] Quarterly vulnerability scans report
- [ ] Annual penetration test report
- [ ] Internal security assessment report
- [ ] Third-party security audit report

### Technical Controls
- [ ] Firewall configuration documentation
- [ ] Network diagram with segmentation
- [ ] Encryption key management documentation
- [ ] Access control matrix
- [ ] Logging and monitoring configuration

### Administrative Controls
- [ ] Security policies and procedures
- [ ] Employee security training records
- [ ] Vendor management documentation
- [ ] Incident response plan and testing records
- [ ] Business continuity and disaster recovery plans

---

## Identified Gaps and Remediation Plans

### Critical Gaps
1. **Quarterly Penetration Testing**: Currently only annual testing scheduled
   - **Risk**: Potential unknown vulnerabilities
   - **Remediation**: Engage qualified third party for quarterly testing
   - **Timeline**: Q2 2026

### Moderate Gaps
1. **Automated Firewall Rule Review**: Manual process currently in place
   - **Risk**: Misconfigured rules could expose data
   - **Remediation**: Deploy automated rule validation tooling
   - **Timeline**: Q3 2026

### Minor Gaps
1. **Enhanced Access Logging**: Could improve detail of access logs
   - **Risk**: Limited forensic capabilities
   - **Remediation**: Enhance logging in next sprint
   - **Timeline**: Q1 2026

---

## Quarterly Review Process

### Review Schedule
- **Frequency**: Quarterly
- **Participants**: Security Team, Development Team, Operations Team, Compliance Officer
- **Deliverables**: Updated compliance status, gap analysis, remediation tracking

### Review Activities
1. Validate existing controls remain effective
2. Identify new threats and vulnerabilities
3. Update risk assessments
4. Review and update policies/procedures
5. Verify compliance evidence is current
6. Update remediation timelines

### Approval Process
- **Primary Reviewer**: CISO
- **Secondary Reviewer**: Compliance Officer
- **Final Approval**: CTO

---

## Attestation

By signing below, we attest that this assessment accurately reflects the security controls in place for protecting cardholder data as of the date of this report.

**Security Officer**: _________________ **Date**: _________

**Compliance Officer**: _________________ **Date**: _________

**CTO**: _________________ **Date**: _________