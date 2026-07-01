package org.chenile.security.auth.framework.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class JwtClaimUtilsTest {

    @Test
    void claimOrDefaultUsesPrimaryThenFallbacks() {
        JwtAuthenticationToken auth = auth(jwtBuilder()
                .claim("preferred_username", "alice")
                .build());

        assertThat(JwtClaimUtils.claimOrDefault(auth, "user_id", "", "fallback"))
                .isEqualTo("fallback");
        assertThat(JwtClaimUtils.claimOrDefault(auth, "preferred_username", "fallback"))
                .isEqualTo("alice");
    }

    @Test
    void splitHeaderValuesTrimsSortsAndRemovesBlanks() {
        assertThat(JwtClaimUtils.splitHeaderValues("orders:read, , bridge:invoke,orders:write"))
                .containsExactly("bridge:invoke", "orders:read", "orders:write");
        assertThat(JwtClaimUtils.splitHeaderValues(" ")).isEmpty();
    }

    @Test
    void extractAclsPrefersRolesThenLegacyAclsThenAuthorities() {
        JwtAuthenticationToken withRoles = auth(jwtBuilder()
                .claim("roles", List.of("z-no-colon", "orders:read", "bridge:invoke", "orders:read"))
                .claim("acls", List.of("legacy:read"))
                .build());
        assertThat(JwtClaimUtils.extractAcls(withRoles))
                .containsExactly("bridge:invoke", "orders:read");

        JwtAuthenticationToken withAcls = auth(jwtBuilder()
                .claim("roles", List.of("user"))
                .claim("acls", List.of("legacy:read", "legacy:write"))
                .build());
        assertThat(JwtClaimUtils.extractAcls(withAcls))
                .containsExactly("legacy:read", "legacy:write");

        JwtAuthenticationToken withAuthorities = new JwtAuthenticationToken(
                jwtBuilder().build(),
                List.of(() -> "SCOPE_gateway.access", () -> "orders:read"));
        assertThat(JwtClaimUtils.extractAcls(withAuthorities))
                .containsExactly("SCOPE_gateway.access", "orders:read");
    }

    private JwtAuthenticationToken auth(Jwt jwt) {
        return new JwtAuthenticationToken(jwt, List.of(() -> "SCOPE_gateway.access"));
    }

    private Jwt.Builder jwtBuilder() {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:9000/realms/tenant-alpha")
                .subject("alice");
    }
}
