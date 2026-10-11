# User Profile Module - API Architecture & BIR Statutory Compliance

This document specifies the architecture and endpoint contracts belonging to the **Profile (`profile`)** module, detailing its role in personal identification, employee metadata, and compliance with BIR CAS regulations alongside the Philippine Data Privacy Act (DPA).

---

## 1. BIR Statutory Compliance Matrix

| Regulation | BIR Requirement | Architectural Implementation in Profile Module |
| :--- | :--- | :--- |
| **Annex B Item 10.g** | Every transaction stamped with creating user's verified identity | The profile module provides the legal name, tax employee identifier, and contact credentials linked 1-to-1 with `auth.users.id`. |
| **Annex B Item 8** | Activity log identifying personnel | Maintains exact identity details of operators executing sales invoicing, journal entries, and system overrides. |
| **Philippine DPA (RA 10173)** | Separation of Personally Identifiable Information (PII) | Decouples personal demographics and physical address fields from authentication credentials and accounting books. |

---

## 2. Profile Lifecycle Endpoints & Lifecycle Integration

### Integration via User Registration & Onboarding Lifecycle
Currently, profile provisioning is executed through the authenticated identity onboarding lifecycle:
- **`POST /api/public/auth/registration`**:
  - Ingests user profile data (`first_name`, `last_name`, `cellphone_number`, address fields) concurrently with credentials.
  - Automatically establishes the `profile.user_profiles` record linked 1-to-1 via `user_id` upon administrator approval.

---

## 3. Dedicated Profile Endpoint Specifications

The following endpoints govern personal profile maintenance for authenticated employees:

### `GET /api/private/profile/me`
- **Purpose**:
  - Retrieves the authenticated employee's full personal profile.
  - Returns legal name, middle name, nickname, contact phone number, gender, date of birth, and structured residential/office address.
- **BIR Statutory Necessity**:
  - **Annex B Item 10.g**: Allows operators to verify their active system profile and identity details used on transactional receipts and journal vouchers.
- **Access**: Private (Authenticated User).
- **Response**: `HTTP 200 OK` with structured profile fields.

---

### `PUT /api/private/profile/me`
- **Purpose**:
  - Updates mutable profile fields (nickname, cellphone number, residential address: street, city, province, postal code).
  - Enforces field-level validation: phone number format, postal code length.
- **BIR Statutory Necessity**:
  - **Annex B Item 8**: Ensures contact and residence records for authorized accounting personnel remain accurate in the event of statutory compliance inquiries or audit investigations.
- **Access**: Private (Authenticated User).
- **Response**: `HTTP 200 OK` with updated profile payload.

---

### `GET /api/private/admin/profiles/{user_id}`
- **Purpose**:
  - Administrative retrieval of any employee's full profile record.
  - Displays complete employee demographics, contact numbers, and registered address.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.a**: Mandated for compliance officers and internal auditors during regulatory reviews to verify the legal identity behind specific user codes (`USR-XXXXX`) attached to disputed accounting entries.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with employee profile details.

---

## 4. Key Structural Invariants

1. **Strict 1-to-1 Entity Relationship**:
   - `user_id` serves as both Primary Key and Foreign Key pointing to `auth.users.id` with `ON DELETE CASCADE`.
2. **Decoupled PII Storage**:
   - Physical address and personal demographics are isolated in the `profile` schema, preventing sensitive PII leakage across general accounting ledger queries.
