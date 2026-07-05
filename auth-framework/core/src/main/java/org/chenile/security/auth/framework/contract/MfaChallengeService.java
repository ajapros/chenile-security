package org.chenile.security.auth.framework.contract;

import org.chenile.security.auth.framework.contract.MfaPolicyService.MfaPolicy;
import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;
import java.time.Instant;

public interface MfaChallengeService {

    MfaChallenge start(ResolvedUserProvider primaryProvider, String clientId, AuthProviderType primaryProviderType, MfaPolicy policy);

    VerifiedMfaChallenge verify(String challengeId, String code);

    record MfaChallenge(
            String challengeId,
            String providerKey,
            AuthProviderType providerType,
            String displayName,
            String destinationHint,
            Instant expiresAt) {
    }

    record VerifiedMfaChallenge(
            String challengeId,
            String realm,
            String email,
            String primaryProviderId,
            String clientId,
            AuthProviderType primaryProviderType,
            String mfaProviderKey,
            AuthProviderType mfaProviderType) {
    }
}
