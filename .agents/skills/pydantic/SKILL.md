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
    tax_amount: Decimal = Field(..., ge=0, decimal_places=2)
```

---

## 3. Field Aliasing & Case Transformations

- **ReactJS Clients**: Rely on `alias_generator=to_camel` and `populate_by_name=True` via `BaseSchema`.
- **External Integrations**: When external APIs require specific casing (e.g. PascalCase or kebab-case), use `alias_generator` or explicit `Field(alias="...")`.
- **Custom Aliases**: Use `Field(alias="customName", validation_alias="...")` when mapping non-standard legacy or third-party properties.

---

## 4. Pydantic v2 Validator Patterns

Always use Pydantic v2 classmethod validators:

```python
from decimal import Decimal
from pydantic import BaseModel, Field, field_validator, model_validator

class InvoiceRequest(BaseModel):
    reference_code: str
    subtotal: Decimal = Field(..., ge=0)
    tax_rate: Decimal = Field(..., ge=0, le=1)
    tax_amount: Decimal = Field(..., ge=0)

    @field_validator("reference_code", mode="before")
    @classmethod
    def sanitize_reference_code(cls, v: str) -> str:
        return str(v).strip().upper() if v else ""

    @model_validator(mode="after")
    def validate_tax_math(self) -> "InvoiceRequest":
        expected_tax = (self.subtotal * self.tax_rate).quantize(Decimal("0.01"))
        if abs(self.tax_amount - expected_tax) > Decimal("0.05"):
            raise ValueError(f"Tax amount ({self.tax_amount}) does not match calculation ({expected_tax}).")
        return self
```

---

## 5. Request & Response DTO Boundaries

1. **Strict Separation**: Separate input schemas (`*Request`) from output schemas (`*Response`). Never reuse ORM models as API inputs or outputs.
2. **Exclusion of Sensitive Data**: Never expose password hashes, secret keys, or internal session tokens in response schemas.
3. **ORM Model Loading**: Ensure `from_attributes=True` in `model_config` to seamlessly convert SQLAlchemy entities via `ResponseSchema.model_validate(orm_obj)`.
