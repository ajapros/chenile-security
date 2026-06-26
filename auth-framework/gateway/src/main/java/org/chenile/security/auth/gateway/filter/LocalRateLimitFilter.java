package org.chenile.security.auth.gateway.filter;

import org.chenile.security.auth.gateway.service.GatewayAuditService;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class LocalRateLimitFilter implements GlobalFilter, Ordered {

    private static final int LIMIT_PER_MINUTE = 60;

    private final Map<String, CounterWindow> counters = new ConcurrentHashMap<>();
    private final GatewayAuditService auditService;

    public LocalRateLimitFilter(GatewayAuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        if (exchange.getRequest().getPath().value().startsWith("/actuator")
                || exchange.getRequest().getPath().value().startsWith("/api/iam")
                || exchange.getRequest().getPath().value().startsWith("/oauth2")
                || exchange.getRequest().getPath().value().startsWith("/.well-known")) {
            return chain.filter(exchange);
        }
        String key = exchange.getRequest().getHeaders().getFirst("x-user-id");
        if (key == null) {
            key = exchange.getRequest().getRemoteAddress() != null
                    ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                    : "anonymous";
        }
        CounterWindow window = counters.compute(key, (currentKey, existing) -> {
            if (existing == null || existing.startedAt().plus(Duration.ofMinutes(1)).isBefore(Instant.now())) {
                return new CounterWindow(Instant.now(), new AtomicInteger(1));
            }
            existing.counter().incrementAndGet();
            return existing;
        });
        if (window.counter().get() > LIMIT_PER_MINUTE) {
            auditService.logAuthorizationFailure(exchange.getRequest().getPath().value(), "rate_limited");
            exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -10;
    }

    private record CounterWindow(Instant startedAt, AtomicInteger counter) {
    }
}
