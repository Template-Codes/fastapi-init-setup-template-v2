from enum import Enum
from typing import Sequence

# Developer defined roles, module, resources, and actions
# Production system permissions or attributes are defined by a dedicated endpoints
# Which then be stored in database.

# THESE ARE JUST INITIAL AND GENERIC ATTRIBUTES

class RoleName(str, Enum):
    """Core System Roles (Generic & Reusable)."""
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    STAFF_USER = "STAFF_USER"
    PUBLIC_USER = "PUBLIC_USER"


ROLE_RANKS: dict[RoleName, int] = {
    RoleName.SUPER_ADMIN: 100,
    RoleName.ADMIN: 50,
    RoleName.STAFF_USER: 10,
    RoleName.PUBLIC_USER: 0,
}


def get_role_rank(role_name: str | RoleName) -> int:
    """Returns numeric authority rank of a role."""
    if isinstance(role_name, str):
        try:
            role_name = RoleName(role_name)
        except ValueError:
            return -1
    return ROLE_RANKS.get(role_name, -1)


def get_user_highest_rank(roles: Sequence[str | RoleName]) -> int:
    """Returns highest numeric rank among a set of assigned roles."""
    if not roles:
        return -1
    return max((get_role_rank(r) for r in roles), default=-1)


ROLE_DESCRIPTIONS: dict[RoleName, str] = {
    RoleName.SUPER_ADMIN: "System Root Administrator with unrestricted operational authority and root bypass privileges.",
    RoleName.ADMIN: "System Administrator with comprehensive operational oversight, vetting, and audit authority.",
    RoleName.STAFF_USER: "Operational staff authorized for day-to-day business actions, profile views, and profile edits.",
    RoleName.PUBLIC_USER: "Default registered public or external user with baseline self-service capabilities.",
}


class ModuleName(str, Enum):
    """Functional system modules (matching src/modules directory names)."""
    AUTHENTICATION = "AUTHENTICATION"
    PROFILE = "PROFILE"
    SESSION = "SESSION"
    RBAC = "RBAC"
    SYSTEM = "SYSTEM"


MODULE_DESCRIPTIONS: dict[ModuleName, str] = {
    ModuleName.AUTHENTICATION: "User identity, credentials, registration onboarding, and access control.",
    ModuleName.PROFILE: "User profile records, personal metadata, and account settings.",
    ModuleName.SESSION: "Active login sessions, terminals, device tracking, and session revocation.",
    ModuleName.RBAC: "Role-Based Access Control hierarchy, permission catalog, and security assignments.",
    ModuleName.SYSTEM: "Core system health, operational parameters, and configuration services.",
}


class ResourceName(str, Enum):
    """
    Target resources / domain entities / endpoints.
    Each resource maps to an endpoint group across system modules.
    """
    USER = "USER"
    REGISTRATION = "REGISTRATION"
    ROLE = "ROLE"
    PERMISSION = "PERMISSION"
    SESSION = "SESSION"
    USER_ROLE = "USER_ROLE"
    ROLE_PERMISSION = "ROLE_PERMISSION"
    DIRECT_PERMISSION = "DIRECT_PERMISSION"
    CHANGE_REQUEST = "CHANGE_REQUEST"


# Detailed descriptions for client UI and administrative metadata
RESOURCE_DESCRIPTIONS: dict[ResourceName, str] = {
    ResourceName.USER: "User account identity records and profile credentials.",
    ResourceName.REGISTRATION: "Pending user registration vetting and approvals.",
    ResourceName.ROLE: "Security roles grouping sets of permissions.",
    ResourceName.PERMISSION: "Granular access rights governing system module actions.",
    ResourceName.SESSION: "Active login sessions, terminals, and forced logouts.",
    ResourceName.USER_ROLE: "Assignment mapping connecting users to specific security roles.",
    ResourceName.ROLE_PERMISSION: "Assignment mapping granting specific permissions to security roles.",
    ResourceName.DIRECT_PERMISSION: "Direct custom user permission grants and explicit denials outside role defaults.",
    ResourceName.CHANGE_REQUEST: "Dual-authorization RBAC change requests requiring multi-tier hierarchical approval.",
}


class ActionName(str, Enum):
    """
    Actions performable on resources.
    Incorporates standard CRUD operations alongside BIR CAS statutory action terminologies
    (BIR Annex B Items 10.b, 10.c, 71; RMC No. 98-2026).
    """
    # Standard CRUD & Administrative Lifecycle
    CREATE = "CREATE"          # Create draft or unposted records
    READ = "READ"              # Retrieve, inspect, or search records
    UPDATE = "UPDATE"          # Modify unposted/draft records before final posting
    DELETE = "DELETE"          # Purge draft/unposted records
    ACCEPT = "ACCEPT"          # Approve registration or workflow state
    REJECT = "REJECT"          # Decline or reject registration or unposted draft
    ASSIGN = "ASSIGN"          # Assign role or permission links
    REVOKE = "REVOKE"          # Revoke assigned privileges or invalidate sessions
    GRANT = "GRANT"            # Grant specific privileges

    # BIR CAS Statutory Actions (Annex B)
    POST = "POST"              # Immutably finalize & post transaction into Books of Accounts (Annex B Item 10.b, 10.c)
    VOID = "VOID"              # Void a posted transaction via reversing journal entries (Annex B Item 10.c)
    VOIDED = "VOIDED"          # Statutory audit tag for voided transactions
    REPRINT = "REPRINT"        # Produce duplicate invoice/receipt with mandatory 'REPRINT' watermark (Annex B Line 71)
    TRANSMIT = "TRANSMIT"      # Auto-transmit e-invoice payload to BIR EIS API (RMC 98-2026)
    GENERATE = "GENERATE"      # Generate official Books of Accounts / BIR tax certificates (Annex B Item 10.d, RR 9-2009)


# Detailed descriptions for actions including BIR statutory references
ACTION_DESCRIPTIONS: dict[ActionName, str] = {
    ActionName.CREATE: "Create draft or unposted entity records",
    ActionName.READ: "Retrieve, view, or search records",
    ActionName.UPDATE: "Modify unposted/draft records before final posting",
    ActionName.DELETE: "Permanently delete draft/unposted records",
    ActionName.ACCEPT: "Approve pending registration or workflow state",
    ActionName.REJECT: "Decline or reject pending registration or workflow",
    ActionName.ASSIGN: "Assign role or permission links to an entity",
    ActionName.REVOKE: "Revoke assigned privileges or invalidate sessions",
    ActionName.GRANT: "Grant specific privilege to a role or user",
    ActionName.POST: "BIR CAS: Immutably post transaction to the Books of Accounts (Annex B Item 10.b, 10.c)",
    ActionName.VOID: "BIR CAS: Void posted transaction via reversing journal entries (Annex B Item 10.c)",
    ActionName.VOIDED: "BIR CAS: Historical audit tag for voided transactions",
    ActionName.REPRINT: "BIR CAS: Reprint receipt/invoice with mandatory REPRINT watermark (Annex B Line 71)",
    ActionName.TRANSMIT: "BIR EIS: Transmit e-invoice JSON payload to BIR EIS API (RMC 98-2026)",
    ActionName.GENERATE: "BIR CAS: Generate official books of accounts or tax certificates (RR 9-2009)",
}


class SystemPermission(str, Enum):
    """
    Standard formatted permission strings: MODULE:RESOURCE:ACTION
    Format: ALL UPPERCASE. Used for type-safe code checks and DB seeding.
    """
    # Authentication & User Management
    AUTHENTICATION_USER_CREATE = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.USER.value}:{ActionName.CREATE.value}"
    AUTHENTICATION_USER_READ = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.USER.value}:{ActionName.READ.value}"
    AUTHENTICATION_USER_UPDATE = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.USER.value}:{ActionName.UPDATE.value}"
    AUTHENTICATION_USER_DELETE = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.USER.value}:{ActionName.DELETE.value}"

    # Registration & Role Approval Endpoints
    AUTHENTICATION_REGISTRATION_ACCEPT = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.REGISTRATION.value}:{ActionName.ACCEPT.value}"
    AUTHENTICATION_REGISTRATION_REJECT = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.REGISTRATION.value}:{ActionName.REJECT.value}"
    AUTHENTICATION_ROLE_GRANT = f"{ModuleName.AUTHENTICATION.value}:{ResourceName.ROLE.value}:{ActionName.GRANT.value}"

    # RBAC Module Endpoints
    RBAC_ROLE_READ = f"{ModuleName.RBAC.value}:{ResourceName.ROLE.value}:{ActionName.READ.value}"
    RBAC_ROLE_ASSIGN = f"{ModuleName.RBAC.value}:{ResourceName.USER_ROLE.value}:{ActionName.ASSIGN.value}"
    RBAC_PERMISSION_ASSIGN = f"{ModuleName.RBAC.value}:{ResourceName.ROLE_PERMISSION.value}:{ActionName.ASSIGN.value}"
    RBAC_DIRECT_PERMISSION_ASSIGN = f"{ModuleName.RBAC.value}:{ResourceName.DIRECT_PERMISSION.value}:{ActionName.ASSIGN.value}"
    RBAC_DIRECT_PERMISSION_REVOKE = f"{ModuleName.RBAC.value}:{ResourceName.DIRECT_PERMISSION.value}:{ActionName.REVOKE.value}"
    RBAC_CHANGE_REQUEST_READ = f"{ModuleName.RBAC.value}:{ResourceName.CHANGE_REQUEST.value}:{ActionName.READ.value}"
    RBAC_CHANGE_REQUEST_APPROVE = f"{ModuleName.RBAC.value}:{ResourceName.CHANGE_REQUEST.value}:{ActionName.ACCEPT.value}"
    RBAC_CHANGE_REQUEST_REJECT = f"{ModuleName.RBAC.value}:{ResourceName.CHANGE_REQUEST.value}:{ActionName.REJECT.value}"

    # Profile Module
    PROFILE_USER_READ = f"{ModuleName.PROFILE.value}:{ResourceName.USER.value}:{ActionName.READ.value}"
    PROFILE_USER_UPDATE = f"{ModuleName.PROFILE.value}:{ResourceName.USER.value}:{ActionName.UPDATE.value}"

    # Session Monitoring Module
    SESSION_SESSION_READ = f"{ModuleName.SESSION.value}:{ResourceName.SESSION.value}:{ActionName.READ.value}"
    SESSION_SESSION_REVOKE = f"{ModuleName.SESSION.value}:{ResourceName.SESSION.value}:{ActionName.REVOKE.value}"


# Bulk Default Permissions per Role (Source of Truth for initial/bulk access)
ROLE_DEFAULT_PERMISSIONS: dict[RoleName, set[SystemPermission]] = {
    RoleName.STAFF_USER: {
        SystemPermission.PROFILE_USER_READ,
        SystemPermission.PROFILE_USER_UPDATE,
    },
    RoleName.ADMIN: {
        SystemPermission.AUTHENTICATION_USER_READ,
        SystemPermission.AUTHENTICATION_REGISTRATION_ACCEPT,
        SystemPermission.AUTHENTICATION_REGISTRATION_REJECT,
        SystemPermission.AUTHENTICATION_ROLE_GRANT,
        SystemPermission.RBAC_ROLE_READ,
        SystemPermission.RBAC_ROLE_ASSIGN,
        SystemPermission.RBAC_PERMISSION_ASSIGN,
        SystemPermission.RBAC_DIRECT_PERMISSION_ASSIGN,
        SystemPermission.RBAC_DIRECT_PERMISSION_REVOKE,
        SystemPermission.RBAC_CHANGE_REQUEST_READ,
        SystemPermission.PROFILE_USER_READ,
        SystemPermission.PROFILE_USER_UPDATE,
        SystemPermission.SESSION_SESSION_READ,
        SystemPermission.SESSION_SESSION_REVOKE,
    },
    RoleName.SUPER_ADMIN: set(SystemPermission),
    RoleName.PUBLIC_USER: set(),
}


def build_rbac_hierarchy() -> list[dict]:
    """
    Constructs the hierarchical Module -> Resource -> Action tree directly from enums.
    
    Structure:
    [
      {
        "name": "AUTHENTICATION",
        "description": "...",
        "resources": [
          {
            "name": "REGISTRATION",
            "description": "...",
            "actions": [
              {
                "name": "ACCEPT",
                "description": "Approve pending registration",
                "permission": "AUTHENTICATION:REGISTRATION:ACCEPT"
              }
            ]
          }
        ]
      }
    ]
    """
    # Group permissions by module and resource
    tree: dict[str, dict[str, list[dict]]] = {}
    for p_enum in SystemPermission:
        parts = p_enum.value.split(":")
        if len(parts) != 3:
            continue
        mod, res, act = parts[0], parts[1], parts[2]

        if mod not in tree:
            tree[mod] = {}
        if res not in tree[mod]:
            tree[mod][res] = []

        act_desc = ""
        try:
            act_desc = ACTION_DESCRIPTIONS.get(ActionName(act), f"Perform {act} action")
        except ValueError:
            act_desc = f"Perform {act} action"

        tree[mod][res].append({
            "name": act,
            "description": act_desc,
            "permission": p_enum.value,
        })

    modules_output: list[dict] = []
    for mod_enum in ModuleName:
        mod_key = mod_enum.value
        if mod_key not in tree:
            continue

        mod_desc = MODULE_DESCRIPTIONS.get(mod_enum, f"{mod_key} module operations.")
        resources_list: list[dict] = []

        for res_enum in ResourceName:
            res_key = res_enum.value
            if res_key not in tree[mod_key]:
                continue

            res_desc = RESOURCE_DESCRIPTIONS.get(res_enum, f"{res_key} resource endpoints.")
            resources_list.append({
                "name": res_key,
                "description": res_desc,
                "actions": tree[mod_key][res_key],
            })

        modules_output.append({
            "name": mod_key,
            "description": mod_desc,
            "resources": resources_list,
        })

    return modules_output
