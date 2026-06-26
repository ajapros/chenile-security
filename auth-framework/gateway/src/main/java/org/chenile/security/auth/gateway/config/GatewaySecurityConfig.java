package org.chenile.security.auth.gateway.config;

import org.chenile.security.auth.gateway.service.GatewayAuditService;
import org.chenile.security.auth.framework.security.IssuerTenantResolver;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class GatewaySecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            GatewayProperties properties,
            GatewayAuditService auditService,
            JwtIssuerReactiveAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver) {
        String requiredAuthority = "SCOPE_" + properties.getSecurity().getRequiredScope();
        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(properties.getSecurity().getPublicPaths().toArray(String[]::new)).permitAll()
                        .anyExchange().hasAuthority(requiredAuthority))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver)
                        .authenticationEntryPoint((exchange, ex) -> {
                            exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                            return auditService.logAuthorizationFailure(
                                            exchange.getRequest().getPath().value(), "authentication_failed")
                                    .then(exchange.getResponse().setComplete());
                        }))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver(
            GatewayProperties properties) {
        Map<String, ReactiveAuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();
        return new JwtIssuerReactiveAuthenticationManagerResolver(issuer -> {
            if (!isTrustedIssuer(properties.getSecurity().getIssuerBase(), issuer)) {
                return Mono.empty();
            }
            return Mono.just(authenticationManagers.computeIfAbsent(
                    issuer,
                    v -> authenticationManagerForIssuer(
                            v,
                            properties.getSecurity().getJwkBaseUri(),
                            properties.getSecurity().getAudience())));
        });
    }

    private ReactiveAuthenticationManager authenticationManagerForIssuer(
            String issuer, String jwkBaseUri, String audience) {
        return new JwtReactiveAuthenticationManager(jwtDecoderForIssuer(issuer, jwkBaseUri, audience));
    }

    private ReactiveJwtDecoder jwtDecoderForIssuer(String issuer, String jwkBaseUri, String expectedAudience) {
        String realm = IssuerTenantResolver.tenantFromIssuer(issuer);
        NimbusReactiveJwtDecoder jwtDecoder =
                NimbusReactiveJwtDecoder.withJwkSetUri(jwkBaseUri + "/realms/" + realm + "/protocol/openid-connect/certs")
                        .build();
        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
            List<String> audiences = jwt.getAudience();
            if (audiences.contains(expectedAudience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Gateway audience is missing", null));
        };
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator));
        return jwtDecoder;
    }

    private boolean isTrustedIssuer(String issuerBase, String issuer) {
        return issuer != null && issuer.startsWith(issuerBase + "/realms/");
    }
}
