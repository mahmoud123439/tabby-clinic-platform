# ADR-001: Local-first clinic application architecture

**Status:** Accepted for this workspace
**Date:** 2026-11-09
**Deciders:** Project owner

## Context

The workspace contains a single-page Arabic clinic site and a small Node.js service. No hosting account, PostgreSQL credentials, email/SMS provider, verified clinic roster, doctor credential documents, or deployment domain is configured. The next increment should make account, provider directory, availability, and appointment flows real without inventing clinic data or transmitting patient records to an unapproved service.

## Decision

Keep a same-origin Node.js service with built-in SQLite and encrypted health payloads for the local, single-instance build. Add normalized tables for users, branches, providers, working hours, and appointments. Use owner-scoped routes and admin-only endpoints to populate provider and branch information. Publish only records marked verified and active. Keep the database and DPAPI-protected local key outside the synced project folder.

## Options considered

### Built-in SQLite

**Pros:** No dependency download, easy local operation, transactional booking and user data, suitable for a single-instance development or small private installation.

**Cons:** Node's built-in SQLite is experimental in the selected Node release; local file operation does not provide managed backups, high availability, multi-region access, or operational monitoring.

### Managed PostgreSQL

**Pros:** Better fit for concurrent production workloads, managed backup/restore, operational monitoring, and multiple service instances.

**Cons:** No provider, credentials, or approved data region is configured in this workspace; adding a connection without those inputs cannot produce a deployable service and may move sensitive health data to an unapproved processor.

## Consequences

- The local service is a working single-instance application, not a certified or production-hosted medical record system.
- A production deployment must select a database and hosting region with the operator, configure secrets and backups, and complete legal/security review before real patient onboarding.
- Doctor credentials, branch addresses, service availability, fees, and accreditations remain unpublished until a privileged operator enters and verifies them.
