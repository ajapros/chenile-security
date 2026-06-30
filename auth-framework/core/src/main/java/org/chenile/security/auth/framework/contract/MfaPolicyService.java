package org.chenile.security.auth.framework.contract;

import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;
import java.time.Duration;
import java.util.List;

public interface MfaPolicyService {

    MfaPolicy evaluate(ResolvedUserProvider primaryProvider, String clientId, AuthProviderType primaryProviderType);

    record MfaPolicy(
            boolean required,
            String providerKey,
            AuthProviderType providerType,
            String displayName,
            String destinationHint,
            Duration challengeTtl,
            List<AuthProviderType> allowedProviderTypes) {

        public static MfaPolicy notRequired() {
            return new MfaPolicy(false, null, null, null, null, Duration.ZERO, List.of());
        }
    }
}
