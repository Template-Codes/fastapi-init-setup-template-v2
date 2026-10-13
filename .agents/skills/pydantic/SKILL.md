---
# pydantic-v2-data-modeling
Description:
  Pydantic v2 schema modeling standards including Decimal enforcement for financial amounts, field alias mappings, strict field/model validators, and request/response DTO boundaries.
---

# Pydantic v2 Data Modeling Standards

This skill defines the schema modeling rules, financial precision standards, validation patterns, and DTO boundaries across the XCOM ERP backend.

---

## 1. Core Schema Bases

- **Standard ERP API Base (`src/base/schema.py`)**: Inherit from `BaseSchema` for general ERP endpoints. Automatically applies `to_camel` alias generation for ReactJS frontend clients:
```python
from base.schema import BaseSchema

class UserResponse(BaseSchema):
    user_id: UUID
    first_name: str
    # Serializes to {"userId": "...", "firstName": "..."} while accepting snake_case
```
- **BIR EIS Integration Base (`src/modules/eis/eis_schema.py`)**: Inherit from `EisBirBaseModel` for BIR submissions. Enforces PascalCase and `extra="forbid"`:
```python
class EisBirBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid", from_attributes=True)
```

---

## 2. Financial Precision: Mandatory `Decimal`

> [!IMPORTANT]
> **Zero Float Rule for Currency**: Never use `float` for monetary amounts, tax computations, discounts, or exchange rates. Always use `Decimal` from Python's standard `decimal` module to prevent IEEE-754 floating-point rounding errors.

```python
from decimal import Decimal
from pydantic import BaseModel, Field

class LineItemSchema(BaseModel):
    unit_cost: Decimal = Field(..., ge=0, decimal_places=4)
    sales_amount: Decimal = Field(..., ge=0, decimal_places=2)
    vat_amount: Decimal = Field(..., ge=0, decimal_places=2)
```

---

## 3. Field Aliasing & Case Transformations

- **ReactJS Clients**: Rely on `alias_generator=to_camel` and `populate_by_name=True` via `BaseSchema`.
- **BIR EIS Payloads**: Use explicit PascalCase field names (`Tin`, `BranchCd`, `VATAmt`, `ItemList`) with exact length constraints matching the BIR JSON schema.
- **Custom Aliases**: Use `Field(alias="customName", validation_alias="...")` when mapping non-standard legacy or third-party properties.

---

## 4. Pydantic v2 Validator Patterns

Always use Pydantic v2 classmethod validators:

```python
from pydantic import field_validator, model_validator

class InvoiceRequest(BaseModel):
    branch_code: str
    vatable_sales: Decimal
    vat_amount: Decimal

    @field_validator("branch_code", mode="before")
    @classmethod
    def pad_branch_code(cls, v: str) -> str:
        return str(v).strip().zfill(5)[:5] if v else "00000"

    @model_validator(mode="after")
    def validate_vat_math(self) -> "InvoiceRequest":
        expected_vat = (self.vatable_sales * Decimal("0.12")).quantize(Decimal("0.01"))
        if abs(self.vat_amount - expected_vat) > Decimal("0.05"):
            raise ValueError(f"VAT amount ({self.vat_amount}) does not match 12% calculation ({expected_vat}).")
        return self
```

---

## 5. Request & Response DTO Boundaries

1. **Strict Separation**: Separate input schemas (`*Request`) from output schemas (`*Response`). Never reuse ORM models as API inputs or outputs.
2. **Exclusion of Sensitive Data**: Never expose password hashes, secret keys, or internal session tokens in response schemas.
3. **ORM Model Loading**: Ensure `from_attributes=True` in `model_config` to seamlessly convert SQLAlchemy entities via `ResponseSchema.model_validate(orm_obj)`.
