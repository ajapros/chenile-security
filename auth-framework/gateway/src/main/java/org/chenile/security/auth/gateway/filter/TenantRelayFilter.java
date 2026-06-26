package org.chenile.security.auth.gateway.filter;

import org.chenile.security.auth.gateway.config.GatewayProperties;
import org.chenile.security.auth.gateway.service.GatewayAuditService;
import org.chenile.security.auth.framework.security.IssuerTenantResolver;
import org.chenile.security.auth.framework.security.JwtClaimUtils;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

@Component
public class TenantRelayFilter implements GlobalFilter, Ordered {

    private final GatewayAuditService auditService;
    private final GatewayProperties properties;

    public TenantRelayFilter(
            GatewayAuditService auditService,
            GatewayProperties properties) {
        this.auditService = auditService;
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .flatMap(authentication -> {
                    if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                        String tenantId = IssuerTenantResolver.tenantFromJwt(jwtAuthenticationToken.getToken());
                        String userId = JwtClaimUtils.claimOrDefault(
                                jwtAuthenticationToken,
                                "user_id",
                                jwtAuthenticationToken.getToken().getClaimAsString("preferred_username"),
                                jwtAuthenticationToken.getToken().getClaimAsString("azp"),
                                jwtAuthenticationToken.getToken().getSubject(),
                                "unknown");
                        auditService.logAuthorizedRequest(exchange.getRequest().getPath().value(), userId, tenantId);
                        return chain.filter(exchange.mutate()
                                .request(builder -> {
                                    if (!properties.getRelay().isForwardAuthorization()) {
                                        builder.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION));
                                    }
                                    properties.getRelay().getHeaders().forEach(header -> {
                                        if (StringUtils.hasText(header.getName())) {
                                            builder.headers(headers -> headers.remove(header.getName()));
                                        }
                                        relayHeader(jwtAuthenticationToken, header)
                                                .forEach(value -> builder.header(header.getName(), value));
                                    });
                                })
                                .build());
                    }
                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return -5;
    }

    private List<String> relayHeader(
            JwtAuthenticationToken authentication,
            GatewayProperties.Header header) {
        if (!StringUtils.hasText(header.getName()) || !StringUtils.hasText(header.getClaim())) {
            return List.of();
        }
        Object claim = claimValue(authentication, header.getClaim());
        if (claim == null) {
            return List.of();
        }
        String value = formatClaim(claim, header.getFormat());
        return StringUtils.hasText(value) ? List.of(value) : List.of();
    }

    private Object claimValue(JwtAuthenticationToken authentication, String claimName) {
        if ("tenant".equals(claimName)) {
            return IssuerTenantResolver.tenantFromJwt(authentication.getToken());
        }
        if ("acls".equals(claimName)) {
            return JwtClaimUtils.extractAcls(authentication);
        }
        if ("user_id".equals(claimName)) {
            return JwtClaimUtils.claimOrDefault(
                    authentication,
                    "user_id",
                    authentication.getToken().getClaimAsString("preferred_username"),
                    authentication.getToken().getClaimAsString("azp"),
                    authentication.getToken().getSubject(),
                    "");
        }
        return authentication.getToken().getClaims().get(claimName);
    }

    private String formatClaim(Object claim, String format) {
        if ("json".equalsIgnoreCase(format)) {
            return toJson(claim);
        }
        if (claim instanceof Collection<?> values) {
            return values.stream()
                    .map(String::valueOf)
                    .filter(StringUtils::hasText)
                    .sorted()
                    .reduce((left, right) -> left + "," + right)
                    .orElse("");
        }
        if (claim instanceof Map<?, ?>) {
            return toJson(claim);
        }
        return String.valueOf(claim);
    }

    private String toJson(Object claim) {
        if (claim instanceof Map<?, ?> map) {
            return map.entrySet().stream()
                    .map(entry -> quote(String.valueOf(entry.getKey())) + ":" + toJson(entry.getValue()))
                    .reduce((left, right) -> left + "," + right)
                    .map(value -> "{" + value + "}")
                    .orElse("{}");
        }
        if (claim instanceof Collection<?> values) {
            return values.stream()
                    .map(this::toJson)
                    .reduce((left, right) -> left + "," + right)
                    .map(value -> "[" + value + "]")
                    .orElse("[]");
        }
        if (claim instanceof Number || claim instanceof Boolean) {
            return String.valueOf(claim);
        }
        return quote(String.valueOf(claim));
    }

    private String quote(String value) {
        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }
}
