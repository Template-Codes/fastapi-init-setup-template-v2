# BIR EIS Compliance Module - API Endpoints & Statutory Invariants

This document specifies the internal endpoints belonging to the **Electronic Invoicing System (`eis`)** module (`src/modules/eis/eis_router.py`), detailing their functional purpose and regulatory compliance necessity under Philippine BIR EIS v2.0 standards.

---

## 1. BIR Statutory Compliance Matrix

| Regulation | BIR Requirement | Architectural Implementation in EIS Endpoints |
| :--- | :--- | :--- |
| **RMC No. 98-2026 §IV.4-6** | Mandatory electronic invoice transmission within statutory deadlines | Batch packaging of sales invoices, RSA signature signing, AES-128-CBC encryption, and machine dispatch to BIR EIS API. |
| **RMC No. 98-2026 §IV.7** | Invoice validation & clearance receipting | Queries clearance status and per-invoice error codes (`E01`-`E14`, `SYN`) using official BIR `submitId`. |
| **Annex B Item 10.c & RMC 98-2026 §IV.8** | Immutability & Re-transmission Lineage | Retry transmissions point back to `parent_transmission_id`, preserving historical failure records rather than overwriting in-place. |
| **RR No. 17-2013 / RR No. 5-2014** | 10-year statutory data retention of books and records | Paginated retrieval of encrypted payloads (`raw_request`) and official BIR server receipts (`raw_response`). |

---

## 2. Electronic Invoicing Endpoints

### `POST /api/internal/eis/transmit`
- **Purpose**:
  - Validates and packages a batch of CAS sales invoices/receipts (up to 1,000 documents per batch).
  - Validates mandatory fields: 24-character `EisUniqueId`, seller/buyer TINs, 5-digit branch codes, VAT breakdown, and permit numbers (`PTU`/`AC`).
  - Performs RSA digital signing (PKCS#1 v1.5 with SHA-256) and AES-128-CBC encryption.
  - Transmits payload to the BIR EIS portal and logs the batch in `eis.eis_transmissions`.
- **BIR Statutory Necessity**:
  - **RMC No. 98-2026 §IV.4-6 & EIS API Guide**: Fulfills the legal obligation of covered CAS taxpayers to report sales transactions electronically to the BIR EIS within three (3) calendar days from issuance.
- **Access**: Internal Microservice / Gateway (`/api/internal/eis`).
- **Response**: `HTTP 200 OK` with transmission ID, `submit_id`, batch status, and count of processed invoices.

---

### `GET /api/internal/eis/status/{submit_id}`
- **Purpose**:
  - Queries transmission audit log status and per-invoice clearance results for a given `submit_id`.
  - Parses BIR response codes: returns `SUCCESS` or `FAILED` along with specific error codes (e.g. `E01` Invalid TIN, `E14` Duplicate Sequence) and error messages.
- **BIR Statutory Necessity**:
  - **RMC No. 98-2026 §IV.7 & EIS API Guide**: Confirms whether transmitted invoices have been formally accepted or rejected by the BIR tax engine, enabling accounting personnel to reconcile sales ledgers with tax clearance receipts.
- **Access**: Internal Microservice / Gateway.
- **Response**: `HTTP 200 OK` with batch summary and per-invoice item breakdown.

---

### `POST /api/internal/eis/retransmit/{transmission_id}`
- **Purpose**:
  - Re-submits a previously failed or partially rejected batch transmission.
  - Generates a fresh `submit_id` while establishing a database foreign key link to `parent_transmission_id`.
- **BIR Statutory Necessity**:
  - **Annex B Item 10.c & RMC No. 98-2026 §IV.8**: Strictly prevents in-place mutation of rejected accounting records. Maintaining parent-child retry lineage provides non-repudiation and proves to tax auditors that corrections were submitted with full historical transparency.
- **Access**: Internal Microservice / Gateway.
- **Response**: `HTTP 200 OK` with new retry submission receipt linked to parent transmission.

---

### `GET /api/internal/eis/transmissions`
- **Purpose**:
  - Paginated inquiry endpoint listing historical EIS transmission batches.
  - Supports filtering by transmission status (`PENDING`, `PROCESSING`, `SUCCESS`, `FAILED`, `PARTIAL_FAILED`).
  - Returns raw encrypted request bodies and unparsed server responses.
- **BIR Statutory Necessity**:
  - **RR No. 17-2013 / RR No. 5-2014 & Annex B Line 175**: Satisfies the 10-year statutory data retention and audit examination mandate. Allows BIR auditors to inspect transmission timestamps, cryptographic payloads, and official acknowledgement receipts for any tax period.
- **Access**: Internal Microservice / Gateway.
- **Response**: `HTTP 200 OK` with paginated transmission records.
