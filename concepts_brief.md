# Account-Linked Medical Record and Results Upload

* **Author:** Codex
* **Date:** 2026-11-09

## Overview

When a person creates an account, the application creates a private patient profile. The patient can upload a lab result or imaging report, and the uploaded item appears in that account's medical record immediately after the server confirms storage. The patient may also enter a visit, diagnosis, treatment, medication, surgery, or allergy as a self-reported item. A separate account cannot read or download another person's file.

The existing project is an Arabic clinic discovery page. This change replaces its mock patient and doctor data with a Node server, SQLite record store, encrypted profile and file payloads, session-based account access, a consent record, and a result upload flow. It also provides admin-managed branches, doctors, working hours, appointment booking, and tracked requests for hospitals, home visits, phone/video consults, medicine delivery, lab tests, and imaging. Directory entries only become public after an administrator enters a review reference and activates them. This is an accountable manual step, not an automated check against a licensing authority. The five requested neighborhoods remain unpublished branch drafts. No actual doctor, active clinic, service location, price, license, or accreditation has been supplied and verified, so none is presented as real.

## Analysis

Medical reports and the health profile are sensitive. The application must keep records private to their account, encrypt medical payloads at rest, validate file types and size, and avoid exposing file bytes in the regular record listing. The upload status must say that the file is awaiting clinician review; uploading a report does not interpret or approve it.

The server records explicit consent and an audit event, but these features do not establish legal compliance. Egyptian Law 151/2020 treats health information as sensitive personal data; licensing, consent, security, retention, and other obligations need review by the actual operator and qualified counsel before real patient onboarding. Node's built-in SQLite module is still experimental; the local implementation is not a production hosting recommendation.

The current screen intentionally shows no doctor cards. The missing inputs are a verified doctor roster (name, branch, specialty, qualification, license, years of experience, schedule, fee), operating branch addresses, and lab/radiology licenses, equipment, accreditation scope, and price lists.

## Goals vs. Non-Goals

* **In-scope goals:** Automatically create one patient profile per account; encrypt stored profile details, contact fields, and uploaded result payloads; let a logged-in patient upload PDF, JPEG, PNG, or DICOM results up to 15 MB; immediately list uploaded and self-reported items in the patient's record; support visit, diagnosis, treatment, medication, surgery, and allergy items marked as patient-entered and unverified; allow only the owner to download files; record consent and access events; give an administrator tools to enter branches/providers, retain review references, and set schedules; publish only manually activated providers at active branches; let patients book open clinic slots and send tracked requests for other service types, labs, and imaging; remove invented provider and sample patient content; document local operation and limits.
* **Out-of-scope non-goals:** Claim legal compliance or accreditation; onboard real patients before the operator completes required approvals; claim any doctor, branch, lab, imaging unit, or price belongs to this network without verification; automatically validate medical licenses against an authority; provide clinician roles to verify diagnoses or prescriptions, LIS/PACS integrations, verified email or phone, password recovery, backup and recovery, key rotation, or production monitoring.

## Alternatives Weighed

* Browser local storage was removed for patient records because it does not isolate server access and cannot safely support a shared account-based medical file.
* Generated physician names and patient histories were removed because they could be mistaken for real professionals or medical information.
* Uploading files to a separate third-party file service was not added because no approved provider, data-processing agreement, region, or access policy was supplied.
* The built-in Node SQLite database is used for local setup to avoid external dependencies. It is an interim local choice; a production deployment needs a reviewed stable database and managed encrypted storage.

## Key Decisions & Staging for Next Steps

1. Registration creates the patient profile transactionally with the account and stores a versioned consent timestamp.
2. The application encrypts personal profile data and report contents with AES-256-GCM; the encryption key is supplied outside source control.
3. Uploaded results appear immediately as uploaded and pending clinician review. The application never claims to interpret them.
4. Clinic booking is available only for public verified doctors and open schedule slots. Other service requests are stored for manual review and explicitly remain unconfirmed until the operator has real partner coverage and responds.
5. Before real patient use: legal/security review of the Egyptian data protection requirements; verified legal notice, retention, rights, and incident process; secure production hosting and database; managed secret storage, key rotation, backup and restore; verified identities, roles, contact recovery, and multifactor authentication; clinical data-entry and review workflows; and complete verified clinic, provider, license, accreditation, and service-price data.

## Sources

* Egypt Personal Data Protection Law 151/2020, official Arabic government announcement: https://sis.gov.eg/ar/الرئاسة/شئون-داخلية/القرارات-الرئاسية/الرئيس-السيسىي-ي-صّد-ق-على-قانون-حماية-البيانات-الشخصية/
* Law 151/2020 PDF hosted by Egypt's Ministry of Communications and Information Technology: https://mcit.gov.eg/Upcont/Documents/Reports%20and%20Documents_1232021000_Law_No_151_2020_Personal_Data_Protection.pdf
* GAHAR facility accreditation standards: https://gahar.gov.eg/en/content-layout/accreditation-standards
* ISO 15189:2022 medical laboratory requirements: https://committee.iso.org/standard/15189
