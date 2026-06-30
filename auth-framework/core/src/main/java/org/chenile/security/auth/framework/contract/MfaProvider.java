package org.chenile.security.auth.framework.contract;

import org.chenile.security.auth.framework.contract.MfaPolicyService.MfaPolicy;
import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;

public interface MfaProvider {

    String providerKey();

    AuthProviderType providerType();

    String destinationHint(ResolvedUserProvider primaryProvider, MfaPolicy policy);

    boolean verify(ResolvedUserProvider primaryProvider, MfaPolicy policy, String code);
}
