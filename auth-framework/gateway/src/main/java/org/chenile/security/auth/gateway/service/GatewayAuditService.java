package org.chenile.security.auth.gateway.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class GatewayAuditService {

    private static final Logger log = LoggerFactory.getLogger("GATEWAY_AUDIT");

    private final Counter authorizationFailureCounter;

    public GatewayAuditService(MeterRegistry meterRegistry) {
        this.authorizationFailureCounter = meterRegistry.counter("chenile.security.gateway.authorization.failure");
    }

    public void logAuthorizedRequest(String path, String userId, String tenantId) {
        log.info("event_type=gateway_authorized path={} user_id={} tenant_id={}", path, userId, tenantId);
    }

    public Mono<Void> logAuthorizationFailure(String path, String reason) {
        authorizationFailureCounter.increment();
        log.warn("event_type=gateway_authorization_failure path={} reason={}", path, reason);
        return Mono.empty();
    }
}
