package org.chenile.security.auth.framework.audit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResourceAuditService {

    private final Logger log;
    private final String serviceName;
    private final Counter tokenValidationFailureCounter;

    public ResourceAuditService(
            MeterRegistry meterRegistry,
            String loggerName,
            String serviceName,
            String counterName) {
        this.log = LoggerFactory.getLogger(loggerName);
        this.serviceName = serviceName;
        this.tokenValidationFailureCounter = meterRegistry.counter(counterName);
    }

    public void logTokenValidationFailure(String path, String reason) {
        tokenValidationFailureCounter.increment();
        log.warn("event_type=token_validation_failure service={} path={} reason={}", serviceName, path, reason);
    }
}
