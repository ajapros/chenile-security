package org.chenile.security.auth.framework.security;

import org.springframework.security.access.AccessDeniedException;

public final class TenantAccessPolicy {

    private static final String PLATFORM_TENANT_PROPERTY = "chenile.security.tenancy.platform-tenant";
    private static final String PLATFORM_TENANT_ENV = "CHENILE_SECURITY_TENANCY_PLATFORM_TENANT";

    private TenantAccessPolicy() {
    }

    public static String effectiveTenant(RequestSecurityContext context) {
        return JwtClaimUtils.firstNonBlank(context.tenantId(), context.headerTenantId(), "unknown");
    }

    public static boolean isPlatformTenant(String tenantId) {
        return platformTenant().equalsIgnoreCase(tenantId);
    }

    public static void assertRelayMatchesTenant(RequestSecurityContext context) {
        String tenantId = effectiveTenant(context);
        String relayedTenantId = context.headerTenantId();
        if (relayedTenantId == null || relayedTenantId.isBlank()) {
            return;
        }
        if (isPlatformTenant(tenantId) || tenantId.equals(relayedTenantId)) {
            return;
        }
        throw new AccessDeniedException("Tenant header does not match authenticated tenant");
    }

    private static String platformTenant() {
        String propertyValue = System.getProperty(PLATFORM_TENANT_PROPERTY);
        if (propertyValue != null && !propertyValue.isBlank()) {
            return propertyValue;
        }
        String environmentValue = System.getenv(PLATFORM_TENANT_ENV);
        if (environmentValue != null && !environmentValue.isBlank()) {
            return environmentValue;
        }
        return "platform";
    }
}
