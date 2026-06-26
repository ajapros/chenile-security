package org.chenile.security.auth.framework.security;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

public class ResourceServerAuthenticationManagerFactory {

    public JwtIssuerAuthenticationManagerResolver createResolver(
            String issuerBase,
            String jwkBaseUri,
            String requiredAudience) {
        Map<String, AuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();
        return new JwtIssuerAuthenticationManagerResolver(issuer -> {
            if (!isTrustedIssuer(issuerBase, issuer)) {
                return null;
            }
            return authenticationManagers.computeIfAbsent(
                    issuer, value -> authenticationManagerForIssuer(value, jwkBaseUri, requiredAudience));
        });
    }

    private AuthenticationManager authenticationManagerForIssuer(
            String issuer,
            String jwkBaseUri,
            String requiredAudience) {
        JwtAuthenticationProvider provider =
                new JwtAuthenticationProvider(jwtDecoderForIssuer(issuer, jwkBaseUri, requiredAudience));
        return provider::authenticate;
    }

    private NimbusJwtDecoder jwtDecoderForIssuer(
            String issuer,
            String jwkBaseUri,
            String requiredAudience) {
        String realm = IssuerTenantResolver.tenantFromIssuer(issuer);
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(
                        jwkBaseUri + "/realms/" + realm + "/protocol/openid-connect/certs")
                .build();
        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
        jwtDecoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator(requiredAudience)));
        return jwtDecoder;
    }

    private OAuth2TokenValidator<Jwt> audienceValidator(String requiredAudience) {
        return jwt -> {
            List<String> audiences = jwt.getAudience();
            if (audiences.contains(requiredAudience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Expected audience " + requiredAudience, null));
        };
    }

    private boolean isTrustedIssuer(String issuerBase, String issuer) {
        return issuer != null && issuer.startsWith(issuerBase + "/realms/");
    }
}
