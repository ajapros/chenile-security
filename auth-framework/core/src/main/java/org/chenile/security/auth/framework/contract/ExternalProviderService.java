package org.chenile.security.auth.framework.contract;

import java.util.List;

public interface ExternalProviderService {

    ProviderConfigDefinition providerConfig(String realm, String providerKey, AuthProviderType providerType);

    record ProviderConfigDefinition(
            String realm,
            String providerKey,
            AuthProviderType providerType,
            String clientId,
            String clientSecret,
            String authorizationUri,
            String tokenUri,
            String userInfoUri,
            List<String> scopes) {
    }
}
