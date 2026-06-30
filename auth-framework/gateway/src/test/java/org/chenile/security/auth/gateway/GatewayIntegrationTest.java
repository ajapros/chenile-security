package org.chenile.security.auth.gateway;

import org.chenile.security.auth.gateway.filter.TenantRelayFilter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import java.util.LinkedHashMap;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = {
                "spring.main.allow-bean-definition-overriding=true",
                "chenile.security.gateway.relay.headers[0].name=x-tenant-id",
                "chenile.security.gateway.relay.headers[0].claim=tenant",
                "chenile.security.gateway.relay.headers[1].name=x-user-id",
                "chenile.security.gateway.relay.headers[1].claim=user_id",
                "chenile.security.gateway.relay.headers[2].name=x-acls",
                "chenile.security.gateway.relay.headers[2].claim=acls",
                "chenile.security.gateway.relay.headers[3].name=x-chenile-tenant-id",
                "chenile.security.gateway.relay.headers[3].claim=tenant",
                "chenile.security.gateway.relay.headers[4].name=x-chenile-auth-user",
                "chenile.security.gateway.relay.headers[4].claim=user_id",
                "chenile.security.gateway.relay.headers[5].name=x-chenile-deviceid",
                "chenile.security.gateway.relay.headers[5].claim=device_id",
                "chenile.security.gateway.relay.headers[6].name=x-vymo-user-details",
                "chenile.security.gateway.relay.headers[6].claim=user_details",
                "chenile.security.gateway.relay.headers[6].format=json",
                "chenile.security.gateway.relay.headers[7].name=x-vymo-locale",
                "chenile.security.gateway.relay.headers[7].claim=locale",
                "chenile.security.gateway.relay.headers[8].name=vymo-locale",
                "chenile.security.gateway.relay.headers[8].claim=vymo_locale",
                "chenile.security.gateway.relay.headers[9].name=x-chenile-mfa",
                "chenile.security.gateway.relay.headers[9].claim=mfa",
                "chenile.security.gateway.relay.headers[10].name=x-chenile-amr",
                "chenile.security.gateway.relay.headers[10].claim=amr",
                "chenile.security.gateway.relay.headers[11].name=x-chenile-mfa-provider",
                "chenile.security.gateway.relay.headers[11].claim=mfa_provider"
        })
class GatewayIntegrationTest {

    private static final String INTEGRATION_TOKEN =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAvcmVhbG1zL3RlbmFudC1hbHBoYSJ9.signature";
    private static final String NO_SCOPE_TOKEN =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAvcmVhbG1zL3RlbmFudC1hbHBoYSJ9.no-scope";

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private TenantRelayFilter tenantRelayFilter;

    @Value("${chenile.security.demo-ui.allowed-origins:http://localhost:5173,http://127.0.0.1:5173}")
    private String allowedOrigins;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        this.webTestClient = WebTestClient.bindToApplicationContext(applicationContext).build();
    }

    @Test
    void protectedRouteRejectsAnonymousRequests() {
        webTestClient.get()
                .uri("/api/test/echo")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void protectedRouteRelaysTenantHeadersForAuthorizedJwt() {
        Jwt jwt = Jwt.withTokenValue(INTEGRATION_TOKEN)
                .header("alg", "RS256")
                .claim("scope", "gateway.access")
                .claim("scp", java.util.List.of("gateway.access"))
                .claim("user_id", "alice")
                .claim("roles", java.util.List.of("orders:read", "bridge:invoke"))
                .claim("acls", java.util.List.of("orders:read", "bridge:invoke"))
                .claim("device_id", "device-123")
                .claim("user_details", java.util.Map.of("branch", "mumbai", "role", "sales"))
                .claim("locale", "en-IN")
                .claim("vymo_locale", "hi-IN")
                .claim("mfa", true)
                .claim("amr", java.util.List.of("pwd", "otp"))
                .claim("mfa_provider", "email-otp")
                .claim("sub", "alice")
                .claim("iss", "http://localhost:9000/realms/tenant-alpha")
                .claim("aud", java.util.List.of("gateway"))
                .build();
        JwtAuthenticationToken authenticationToken =
                new JwtAuthenticationToken(jwt, java.util.List.of(() -> "SCOPE_gateway.access"));
        org.springframework.web.server.ServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get("/api/test/echo")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + INTEGRATION_TOKEN)
                                .header("x-tenant-id", "spoofed-tenant")
                                .header("x-chenile-tenant-id", "spoofed-chenile-tenant")
                                .build())
                .mutate()
                .principal(Mono.just(authenticationToken))
                .build();
        java.util.concurrent.atomic.AtomicReference<org.springframework.web.server.ServerWebExchange> seenExchange =
                new java.util.concurrent.atomic.AtomicReference<>();

        tenantRelayFilter.filter(exchange, filteredExchange -> {
            seenExchange.set(filteredExchange);
            return Mono.empty();
        }).block();

        org.assertj.core.api.Assertions.assertThat(seenExchange.get()).isNotNull();
        org.assertj.core.api.Assertions.assertThat(seenExchange.get().getRequest().getHeaders().getFirst("x-tenant-id"))
                .isEqualTo("tenant-alpha");
        org.assertj.core.api.Assertions.assertThat(seenExchange.get().getRequest().getHeaders().getFirst("x-user-id"))
                .isEqualTo("alice");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-acls").split(","))
                .containsExactlyInAnyOrder("orders:read", "bridge:invoke");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-tenant-id"))
                .isEqualTo("tenant-alpha");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-auth-user"))
                .isEqualTo("alice");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-deviceid"))
                .isEqualTo("device-123");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-vymo-user-details"))
                .contains("\"role\":\"sales\"", "\"branch\":\"mumbai\"");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-vymo-locale"))
                .isEqualTo("en-IN");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("vymo-locale"))
                .isEqualTo("hi-IN");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-mfa"))
                .isEqualTo("true");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-amr").split(","))
                .containsExactly("otp", "pwd");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-mfa-provider"))
                .isEqualTo("email-otp");
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer " + INTEGRATION_TOKEN);
    }

    @Test
    void configuredRelayHeadersAreOmittedWhenClaimsAreMissing() {
        Jwt jwt = Jwt.withTokenValue(INTEGRATION_TOKEN)
                .header("alg", "RS256")
                .claim("scope", "gateway.access")
                .claim("scp", java.util.List.of("gateway.access"))
                .claim("user_id", "alice")
                .claim("sub", "alice")
                .claim("iss", "http://localhost:9000/realms/tenant-alpha")
                .claim("aud", java.util.List.of("gateway"))
                .build();
        JwtAuthenticationToken authenticationToken =
                new JwtAuthenticationToken(jwt, java.util.List.of(() -> "SCOPE_gateway.access"));
        org.springframework.web.server.ServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get("/api/test/echo").build())
                        .mutate()
                        .principal(Mono.just(authenticationToken))
                        .build();
        java.util.concurrent.atomic.AtomicReference<org.springframework.web.server.ServerWebExchange> seenExchange =
                new java.util.concurrent.atomic.AtomicReference<>();

        tenantRelayFilter.filter(exchange, filteredExchange -> {
            seenExchange.set(filteredExchange);
            return Mono.empty();
        }).block();

        org.assertj.core.api.Assertions.assertThat(seenExchange.get()).isNotNull();
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-chenile-deviceid"))
                .isNull();
        org.assertj.core.api.Assertions.assertThat(
                        seenExchange.get().getRequest().getHeaders().getFirst("x-vymo-user-details"))
                .isNull();
    }

    @Test
    void protectedRouteRejectsJwtWithoutGatewayScope() {
        webTestClient.get()
                .uri("/api/test/echo")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + NO_SCOPE_TOKEN)
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void gatewayAddsCorsHeadersForFrontendOrigin() {
        org.assertj.core.api.Assertions.assertThat(allowedOrigins)
                .contains("http://localhost:5173");
    }

    @TestConfiguration
    static class TestRoutes {

        @Bean
        RouteLocator routeLocator(RouteLocatorBuilder builder) {
            return builder.routes()
                    .route("test-route", route -> route
                            .path("/api/test/**")
                            .filters(filters -> filters.setPath("/mock/echo"))
                            .uri("forward:/mock/echo"))
                    .build();
        }

        @Bean
        @Primary
        ReactiveJwtDecoder reactiveJwtDecoder() {
            return token -> {
                if (NO_SCOPE_TOKEN.equals(token)) {
                    return Mono.just(Jwt.withTokenValue(NO_SCOPE_TOKEN)
                            .header("alg", "RS256")
                            .claim("scope", "")
                            .claim("scp", java.util.List.of())
                            .claim("user_id", "alice")
                            .claim("roles", java.util.List.of("orders:read"))
                            .claim("acls", java.util.List.of("orders:read"))
                            .claim("sub", "alice")
                            .claim("iss", "http://localhost:9000/realms/tenant-alpha")
                            .claim("aud", java.util.List.of("gateway"))
                            .build());
                }
                return Mono.just(Jwt.withTokenValue(INTEGRATION_TOKEN)
                        .header("alg", "RS256")
                        .claim("scope", "gateway.access")
                        .claim("scp", java.util.List.of("gateway.access"))
                        .claim("user_id", "alice")
                        .claim("roles", java.util.List.of("orders:read", "bridge:invoke"))
                        .claim("acls", java.util.List.of("orders:read", "bridge:invoke"))
                        .claim("device_id", "device-123")
                        .claim("user_details", java.util.Map.of("branch", "mumbai", "role", "sales"))
                        .claim("locale", "en-IN")
                        .claim("vymo_locale", "hi-IN")
                        .claim("mfa", true)
                        .claim("amr", java.util.List.of("pwd", "otp"))
                        .claim("mfa_provider", "email-otp")
                        .claim("sub", "alice")
                        .claim("iss", "http://localhost:9000/realms/tenant-alpha")
                        .claim("aud", java.util.List.of("gateway"))
                        .build());
            };
        }

        @Bean
        @Primary
        JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver(
                ReactiveJwtDecoder reactiveJwtDecoder) {
            ReactiveAuthenticationManager authenticationManager =
                    new JwtReactiveAuthenticationManager(reactiveJwtDecoder);
            return new JwtIssuerReactiveAuthenticationManagerResolver(issuer -> Mono.just(authenticationManager));
        }

        @RestController
        static class EchoController {

            @GetMapping("/public/ping")
            java.util.Map<String, String> ping() {
                return java.util.Map.of("status", "ok");
            }

            @GetMapping("/mock/echo")
            java.util.Map<String, String> echo(
                    org.springframework.web.server.ServerWebExchange exchange,
                    @RequestHeader(value = "x-tenant-id", required = false) String tenantId,
                    @RequestHeader(value = "x-user-id", required = false) String userId,
                    @RequestHeader(value = "x-acls", required = false) String acls) {
                java.util.Map<String, String> response = new LinkedHashMap<>();
                response.put("status", "ok");
                response.put("path", exchange.getRequest().getPath().value());
                response.put("tenantId", tenantId == null ? "missing" : tenantId);
                response.put("userId", userId == null ? "missing" : userId);
                response.put("acls", acls == null ? "missing" : acls);
                return response;
            }
        }
    }
}
