package org.chenile.security.auth.framework.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

class TenantAccessPolicyTest {

    @AfterEach
    void clearPlatformTenantOverride() {
        System.clearProperty("chenile.security.tenancy.platform-tenant");
    }

    @Test
    void effectiveTenantPrefersAuthenticatedTenantThenHeader() {
        assertThat(TenantAccessPolicy.effectiveTenant(context("tenant-alpha", "tenant-beta")))
                .isEqualTo("tenant-alpha");
        assertThat(TenantAccessPolicy.effectiveTenant(context("", "tenant-beta")))
                .isEqualTo("tenant-beta");
    }

    @Test
    void assertRelayMatchesTenantAllowsMissingOrMatchingHeader() {
        TenantAccessPolicy.assertRelayMatchesTenant(context("tenant-alpha", null));
        TenantAccessPolicy.assertRelayMatchesTenant(context("tenant-alpha", "tenant-alpha"));
    }

    @Test
    void assertRelayMatchesTenantAllowsPlatformTenant() {
        System.setProperty("chenile.security.tenancy.platform-tenant", "platform-admin");

        TenantAccessPolicy.assertRelayMatchesTenant(context("platform-admin", "tenant-alpha"));
    }

    @Test
    void assertRelayMatchesTenantRejectsSpoofedTenantHeader() {
        assertThatThrownBy(() -> TenantAccessPolicy.assertRelayMatchesTenant(context("tenant-alpha", "tenant-beta")))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Tenant header does not match authenticated tenant");
    }

    private RequestSecurityContext context(String tenantId, String headerTenantId) {
        return new RequestSecurityContext(
                "alice",
                tenantId,
                List.of("orders:read"),
                "token",
                "alice",
                headerTenantId,
                List.of());
    }
}
