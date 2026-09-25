import { deny, DenialCode, type Denial } from "./denial.ts";
import {
  isLevelAllowed,
  isPermissionLevel,
  type PermissionLevel,
  type Permissions,
} from "./permission-levels.ts";
import type { TrustPolicy } from "./trust-policy.ts";

/**
 * Organization-, user-, and enterprise-scoped permissions. Repository-scoped
 * installation tokens can never grant these. Same list as upstream.
 */
export const NON_REPOSITORY_PERMISSIONS: ReadonlyMap<
  string,
  "organization" | "user" | "enterprise"
> = new Map([
  ["custom_properties_for_organizations", "organization"],
  ["members", "organization"],
  ["organization_administration", "organization"],
  ["organization_announcement_banners", "organization"],
  ["organization_copilot_seat_management", "organization"],
  ["organization_custom_org_roles", "organization"],
  ["organization_custom_properties", "organization"],
  ["organization_custom_roles", "organization"],
  ["organization_events", "organization"],
  ["organization_hooks", "organization"],
  ["organization_packages", "organization"],
  ["organization_personal_access_token_requests", "organization"],
  ["organization_personal_access_tokens", "organization"],
  ["organization_plan", "organization"],
  ["organization_projects", "organization"],
  ["organization_secrets", "organization"],
  ["organization_self_hosted_runners", "organization"],
  ["organization_user_blocking", "organization"],
  ["team_discussions", "organization"],
  ["email_addresses", "user"],
  ["followers", "user"],
  ["git_ssh_keys", "user"],
  ["gpg_keys", "user"],
  ["interaction_limits", "user"],
  ["profile", "user"],
  ["starring", "user"],
  ["enterprise_custom_properties_for_organizations", "enterprise"],
]);

export type PermissionResolution =
  | { readonly ok: true; readonly permissions: Permissions }
  | { readonly ok: false; readonly denial: Denial };

function checkOrgMax(
  permission: string,
  level: PermissionLevel,
  maxPermissions: Permissions,
): Denial | undefined {
  const maximum = maxPermissions[permission];
  if (maximum === undefined) {
    return deny(
      DenialCode.PermissionNotInMaxPermissions,
      `permission "${permission}" is not listed in max_permissions`,
      "only permissions explicitly listed in max_permissions are allowed",
    );
  }
  if (maximum === "none") {
    return deny(
      DenialCode.PermissionDenied,
      `permission "${permission}" is explicitly denied`,
      "max_permissions is set to 'none' for this permission",
    );
  }
  if (!isLevelAllowed(level, maximum)) {
    return deny(
      DenialCode.PermissionExceedsMax,
      `permission "${permission}" level "${level}" exceeds org maximum`,
      `max allowed: ${maximum}`,
    );
  }
  return undefined;
}

/**
 * Effective permissions are the intersection of what was requested (or the
 * policy's grant when nothing was requested), what the matched trust policy
 * allows, and the organization-wide `max_permissions` allowlist.
 */
export function resolvePermissions(
  requested: Readonly<Record<string, string>> | undefined,
  policy: TrustPolicy,
  maxPermissions: Permissions,
): PermissionResolution {
  const wanted: Readonly<Record<string, string>> =
    requested && Object.keys(requested).length > 0 ? requested : policy.permissions;
  const granted: Record<string, PermissionLevel> = {};

  for (const [permission, level] of Object.entries(wanted)) {
    const scope = NON_REPOSITORY_PERMISSIONS.get(permission);
    if (scope) {
      return {
        ok: false,
        denial: deny(
          DenialCode.NonRepositoryPermission,
          `permission "${permission}" is ${scope}-scoped`,
          "repository tokens can only be granted repository-scoped permissions",
        ),
      };
    }
    const allowed = policy.permissions[permission];
    if (allowed === undefined) {
      return {
        ok: false,
        denial: deny(
          DenialCode.PermissionNotInPolicy,
          `permission "${permission}" not granted by policy`,
          `policy: ${policy.name}`,
        ),
      };
    }
    if (!isPermissionLevel(level) || !isLevelAllowed(level, allowed)) {
      return {
        ok: false,
        denial: deny(
          DenialCode.PermissionExceedsPolicy,
          `requested "${permission}" level "${level}" exceeds policy maximum "${allowed}"`,
          `policy: ${policy.name}`,
        ),
      };
    }
    const orgDenial = checkOrgMax(permission, level, maxPermissions);
    if (orgDenial) {
      return { ok: false, denial: orgDenial };
    }
    granted[permission] = level;
  }
  return { ok: true, permissions: granted };
}
