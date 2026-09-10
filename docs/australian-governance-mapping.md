# Australian governance mapping

**Review date:** 9 September 2026

This document maps NOVA One artefacts to selected Australian governance sources.
It is an engineering traceability aid, not legal advice, a conformity assessment,
a regulator submission, or a claim of certification. Applicability depends on the
deploying entity, sector, data, people affected, and use case. A signed record is
evidence that an event was recorded; it does not establish that the underlying
decision was lawful, fair, accurate, or effective.

## Status language

| Status | Meaning |
| --- | --- |
| Built-in evidence | NOVA One can generate or verify a relevant technical artefact. |
| Deployment control | The deployer must define, operate, and evidence the control; NOVA One may hold supporting records. |
| Gap | The open-source runtime does not implement or establish the control. |
| Not applicable by default | The source applies only to a particular class of entity or use case. |

## Guidance for AI adoption

The National AI Centre's [essential AI practices](https://www.ai.gov.au/staying-safe-and-responsible/essential-ai-practices)
are current Australian Government guidance for responsible AI use. The detailed
[implementation guidance](https://www.ai.gov.au/staying-safe-and-responsible/essential-ai-practices/guidance-ai-adoption-implementation-guidance)
organises the guidance into six practices. The guidance is not replaced by a NOVA
receipt, and NOVA One does not certify adoption.

| Essential practice | NOVA One contribution | Status and missing evidence |
| --- | --- | --- |
| 1. Decide who is accountable | Actor identifiers, scoped evidence authorisations and local-action receipts can make part of a workflow traceable. | **Built-in evidence:** signed and hash-linked local records. **Gap:** there is no authenticated external-action approval workflow in 0.2.0. **Deployment control:** name accountable officers, define authority, train people, maintain an AI policy and system register, and review supply-chain responsibility. |
| 2. Understand impacts and plan accordingly | Purpose, audience, subject, jurisdiction, provenance hashes, human approvals, and retained decisions can support a use-case evidence file. | **Deployment control:** stakeholder identification and engagement, impact assessment, contestability, remediation, accessibility, and affected-person notices. NOVA One does not determine social impact or fairness. |
| 3. Measure and manage risks | Fixed action rules, expiry and freshness checks, fail-closed verification, a kill switch, idempotency, and audit receipts can evidence specific technical treatments. | **Built-in evidence:** technical checks and outcomes. **Deployment control:** risk appetite, screening, risk assessment, policy design, control effectiveness, incident analysis, model risk, procurement review, and residual-risk acceptance. NOVA One has no general policy DSL or dry-run API. |
| 4. Share essential information | Credentials and receipts carry bounded purpose and evidence references; verification results can be attached to system documentation. | **Deployment control:** public disclosures, AI register, understandable explanations, model/system limitations, supply-chain documentation, and disclosure of AI-generated content. Do not publish secrets, private claims, or correlatable identifiers. |
| 5. Test and monitor | Negative verification, tamper detection, replay rejection, and ledger verification are testable runtime properties. | **Built-in evidence:** technical workflow tests. **Gap:** model quality, bias, safety, drift, red-team, accessibility, environmental, and independent assurance testing are not supplied. The deployer must set acceptance criteria and monitor the AI system. |
| 6. Maintain human control | The runtime can keep an agent proposal separate from a bounded local record action and signed receipt. External execution is unavailable in 0.2.0. | **Built-in evidence:** fixed gates and recorded `record.append` actions. **Gap:** `webhook.dispatch` authorization and execution fail closed because durable delivery and authenticated approval are not implemented. **Deployment control:** competent reviewers, segregation of duties, stop/rollback capability, alternative service paths, escalation, and periodic exercises. |

Recommended evidence package: an AI system register entry; named accountable
people; stakeholder and risk assessments; system/model documentation; test and
monitoring results; incident and dispute records; source authorisations and
snapshots; organisational policy versions and decisions; exact external-action
authorisations; action receipts; and an independent review where risk warrants
it.

## Privacy Act and Australian Privacy Principles

The [Privacy Act 1988](https://www.legislation.gov.au/C2004A03712/latest/text)
and [Australian Privacy Principles](https://www.oaic.gov.au/privacy/australian-privacy-principles)
may apply when personal information is handled. The OAIC also publishes
[guidance on privacy and commercially available AI products](https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/guidance-on-privacy-and-the-use-of-commercially-available-ai-products).
The table is deliberately selective and must be reviewed against all applicable
APPs and other law.

| APP topic | NOVA One contribution | Status and missing evidence |
| --- | --- | --- |
| APP 1 — governance and transparency | Purpose-labelled records and audit trails can support accountability. | **Deployment control:** privacy policy, procedures, enquiries/complaints path, governance, and demonstrable compliance. |
| APP 3 — collection | Data-type allowlists, purpose binding, source authorisation, and selective release can help constrain collection. | **Deployment control:** prove collection is lawful, fair, reasonably necessary, and—where required—consented. A technical allowlist is not that proof. |
| APP 5 — notification | Purpose, audience, source, and requested fields can populate a collection notice. | **Gap:** NOVA One does not deliver or prove comprehension of a compliant notice. |
| APP 6 — use or disclosure | Audience and purpose checks plus evidence-authorisation expiry/revocation can help enforce an approved workflow. | **Deployment control:** establish the primary purpose or valid exception/consent and govern and evidence every downstream disclosure. |
| APP 8 — cross-border disclosure | `jurisdiction` metadata can be recorded on credentials. | **Deployment control:** identify overseas recipients, assess legal requirements, enforce jurisdiction in deployment policy, and implement contractual/technical controls. NOVA's metadata is not an enforcement control, geofencing, or proof of data residency. |
| APP 10 — quality | Authenticated snapshots, hashes, timestamps, freshness rules, and dispute references can support quality review. | **Deployment control:** validate correctness, relevance, completeness, and currentness. Integrity is not truth. |
| APP 11 — security and destruction | Cryptographic integrity, least-data disclosures, expiry, status, and fail-closed checks reduce some risks. | **Deployment control:** reasonable technical and organisational safeguards, retention, deletion/de-identification, access control, incident response, and breach notification. The append-only evidence design can conflict with deletion needs; store personal data off-ledger and commit only a minimised digest where appropriate. |
| APP 12/13 — access and correction | Stable record identifiers and superseding audit entries can reference requests and corrections. | **Gap:** NOVA One does not provide a complete identity-verified access/correction case-management process or erase historical commitments. |

Privacy architecture should keep raw personal information outside the audit
ledger where possible. A hash can still be personal information or enable
correlation in context; use keyed commitments or other deployment controls after
legal and threat-model review rather than assuming hashing anonymises data.

## Commonwealth government AI policy

The Digital Transformation Agency's [Policy for the responsible use of AI in
government, version 2.0](https://www.digital.gov.au/ai/ai-in-government-policy)
is effective from 15 December 2025 and applies to non-corporate Commonwealth
entities subject to its stated scope and exceptions. It includes mandatory
requirements covering accountable officials, transparency, strategy,
operationalisation, use-case accountability, registers, training, and impact
assessment.

NOVA One records may support a use-case file, internal register integration,
approval trail, monitoring evidence, and incident reconstruction. They do not
appoint an accountable official, publish a transparency statement, perform the
required impact assessment, train staff, or demonstrate policy compliance.
Government users must map the current policy requirements and implementation
dates to their agency controls and obtain the required assurance.

## Cyber security guidance

The Australian Signals Directorate describes the [Essential Eight](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight)
as a baseline of mitigation strategies and publishes an [Essential Eight
maturity model](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model).
NOVA One does not implement or assess the Essential Eight. In particular, it does
not manage application control, patching, Office macro settings, user application
hardening, privileged accounts, operating-system MFA, or backups across a
deployment. Its signatures, restrictive filesystem modes, audit verification,
and explicit external-action gates may be inputs to a broader security design,
but no Essential Eight maturity level can be inferred from them.

The [Essential Eight assessment process guide](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-assessment-process-guide)
emphasises credible evidence. Preserve configuration, test results, access logs,
backup-restore results, and independent assessor evidence outside NOVA One as
required. The 2026 ASD consultation on an evolved Essentials series does not by
itself change this mapping; review the final guidance when published.

## APRA-regulated entities

This section is **not applicable by default**. An entity must first determine
whether it and the relevant system are within APRA's prudential framework.

- [CPS 234 Information Security](https://www.apra.gov.au/sites/default/files/cps_234_july_2019_for_public_release.pdf)
  requires APRA-regulated entities to maintain information-security capability
  commensurate with threats and vulnerabilities, implement controls, test their
  effectiveness, and notify APRA in specified circumstances.
- [CPS 230 Operational Risk Management](https://www.apra.gov.au/standards/cps-230)
  is in force in its current form from 1 July 2026 and addresses operational
  risk, critical operations, business continuity, and service-provider risk.

NOVA One audit evidence can support—but cannot replace—control testing,
accountability, incident investigation, service-provider records, and change
approval. It does not establish an information-security capability, operational
resilience, business continuity, provider due diligence, notification, board
oversight, or compliance with either standard. Independent legal, risk, and
assurance review remains necessary.

## Evidence interpretation rules

Use these rules in every governance export or review:

1. Verify the credential or receipt, its current status, purpose, audience,
   subject, challenge where applicable, and the audit ledger before relying on
   fields.
2. Keep the source artefact and the verification result distinct. A matching
   digest proves byte-level binding to the submitted artefact, not accuracy.
3. Record the policy version and approval identity. An AI-generated explanation
   or recommendation is not a control approval.
4. Mark missing controls as missing. Do not translate absence of incidents into
   proof of safety, or a successful demo into production assurance.
5. Obtain independent evidence for controls that require independent testing,
   witnessing, legal interpretation, or regulator acceptance.

## Maintenance

Australian law and guidance change. Review this mapping before each governance
export and at least annually. Preserve the review date, source version or access
date, reviewer, scope, gaps, and changes from the prior mapping.
