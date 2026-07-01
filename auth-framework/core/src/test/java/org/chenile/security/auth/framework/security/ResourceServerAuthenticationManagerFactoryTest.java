package org.chenile.security.auth.framework.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

class ResourceServerAuthenticationManagerFactoryTest {

    @Test
    void createResolverReturnsResolverForConfiguredIssuerBase() {
        ResourceServerAuthenticationManagerFactory factory = new ResourceServerAuthenticationManagerFactory();

        assertThat(factory.createResolver("http://localhost:9000", "http://localhost:9000", "gateway"))
                .isNotNull();
    }

    @Test
    void trustedIssuerRequiresConfiguredRealmPrefix() throws Exception {
        ResourceServerAuthenticationManagerFactory factory = new ResourceServerAuthenticationManagerFactory();
        Method method = ResourceServerAuthenticationManagerFactory.class
                .getDeclaredMethod("isTrustedIssuer", String.class, String.class);
        method.setAccessible(true);

        assertThat((boolean) method.invoke(factory, "http://localhost:9000", "http://localhost:9000/realms/tenant-alpha"))
                .isTrue();
        assertThat((boolean) method.invoke(factory, "http://localhost:9000", "http://evil.example/realms/tenant-alpha"))
                .isFalse();
        assertThat((boolean) method.invoke(factory, "http://localhost:9000", null))
                .isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void audienceValidatorRequiresExpectedAudience() throws Exception {
        ResourceServerAuthenticationManagerFactory factory = new ResourceServerAuthenticationManagerFactory();
        Method method = ResourceServerAuthenticationManagerFactory.class
                .getDeclaredMethod("audienceValidator", String.class);
        method.setAccessible(true);
        OAuth2TokenValidator<Jwt> validator = (OAuth2TokenValidator<Jwt>) method.invoke(factory, "gateway");

        assertThat(validator.validate(jwt(List.of("gateway"))).hasErrors()).isFalse();
        assertThat(validator.validate(jwt(List.of("service-a"))).hasErrors()).isTrue();
    }

    private Jwt jwt(List<String> audience) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("http://localhost:9000/realms/tenant-alpha")
                .subject("alice")
                .audience(audience)
                .build();
    }
}
