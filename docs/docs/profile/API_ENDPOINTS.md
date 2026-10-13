# User Profile Module - API Architecture Specification

This document specifies the architecture and endpoint contracts belonging to the **Profile (`profile`)** module, detailing its role in personal identification, employee metadata, and privacy isolation.

---

## 1. Profile Lifecycle Integration

### Integration via User Registration & Onboarding Lifecycle
Currently, profile provisioning is executed through the authenticated identity onboarding lifecycle:
- **`POST /api/public/auth/register`**:
  - Ingests user profile data (`first_name`, `last_name`, `cellphone_number`, address fields) concurrently with credentials.
  - Automatically establishes the `profile.user_profiles` record linked 1-to-1 via `user_id` upon administrator approval.

---

## 2. Dedicated Profile Endpoint Specifications

The following endpoints govern personal profile maintenance for authenticated users:

### `GET /api/private/profile/me`
- **Purpose**:
  - Retrieves the authenticated user's full personal profile.
  - Returns legal name, middle name, nickname, contact phone number, gender, date of birth, and structured residential/office address.
- **Access**: Private (Authenticated User).
- **Response**: `HTTP 200 OK` with structured profile fields.

---

### `PUT /api/private/profile/me`
- **Purpose**:
  - Updates mutable profile fields (nickname, cellphone number, residential address: street, city, province, postal code).
  - Enforces field-level validation: phone number format, postal code length.
- **Access**: Private (Authenticated User).
- **Response**: `HTTP 200 OK` with updated profile payload.

---

### `GET /api/private/admin/profiles/{user_id}`
- **Purpose**:
  - Administrative retrieval of any user's full profile record.
  - Displays complete user demographics, contact numbers, and registered address.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with profile details.

---

## 3. Key Structural Invariants

1. **Strict 1-to-1 Entity Relationship**:
   - `user_id` serves as both Primary Key and Foreign Key pointing to `auth.users.id` with `ON DELETE CASCADE`.
2. **Decoupled PII Storage**:
   - Physical address and personal demographics are isolated in the `profile` schema, preventing sensitive PII leakage across general ledger queries.
