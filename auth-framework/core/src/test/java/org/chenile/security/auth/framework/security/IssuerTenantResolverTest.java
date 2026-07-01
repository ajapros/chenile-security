package org.chenile.security.auth.framework.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class IssuerTenantResolverTest {

    @Test
    void extractsTenantFromRealmIssuer() {
        assertThat(IssuerTenantResolver.tenantFromIssuer("http://localhost:9000/realms/tenant-alpha"))
                .isEqualTo("tenant-alpha");
    }

    @Test
    void extractsTenantFromRealmIssuerWithAdditionalPath() {
        assertThat(IssuerTenantResolver.tenantFromIssuer("https://auth.example.com/realms/platform/protocol/openid-connect"))
                .isEqualTo("platform");
    }

    @Test
    void returnsUnknownForMissingRealmPath() {
        assertThat(IssuerTenantResolver.tenantFromIssuer(null)).isEqualTo("unknown");
        assertThat(IssuerTenantResolver.tenantFromIssuer(" ")).isEqualTo("unknown");
        assertThat(IssuerTenantResolver.tenantFromIssuer("https://auth.example.com/oauth2/default")).isEqualTo("unknown");
    }

    @Test
    void extractsTenantFromJwtIssuer() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:9000/realms/tenant-beta")
                .subject("bob")
                .claim("scp", List.of("gateway.access"))
                .build();

        assertThat(IssuerTenantResolver.tenantFromJwt(jwt)).isEqualTo("tenant-beta");
    }
}
