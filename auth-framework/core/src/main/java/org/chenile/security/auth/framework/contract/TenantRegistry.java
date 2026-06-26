package org.chenile.security.auth.framework.contract;

import java.util.List;
import java.util.Map;

public interface TenantRegistry {

    RealmDefinition realm(String tenant);

    boolean realmExists(String tenant);

    boolean createRealm(String tenant);

    void registerClient(String tenant, ClientDefinition client);

    ClientDefinition client(String tenant, String clientId);

    UserDefinition user(String tenant, String username);

    boolean matchesUserPassword(UserDefinition user, String rawPassword);

    boolean matchesClientSecret(ClientDefinition client, String rawSecret);

    List<String> allowedScopes(String tenant, String clientId, List<String> requestedScopes);

    List<AuthProviderDefinition> providersForEmail(String email);

    ResolvedUserProvider resolvedProvider(long providerId, String email);

    boolean authenticate(long providerId, String email, String secret);

    List<String> defaultBrowserScopes();

    Map<String, Object> createRealmPayload(String tenant);

    record RealmDefinition(long id, String name, String displayName) {
    }

    record ClientDefinition(
            String clientId,
            String secretHash,
            boolean clientCredentialsEnabled,
            boolean passwordGrantEnabled,
            List<String> allowedScopes) {

        public String secret() {
            return secretHash;
        }
    }

    record UserDefinition(
            long id,
            String realm,
            String username,
            String email,
            String passwordSecretHash,
            List<String> acls) {
    }

    record AuthProviderDefinition(
            long id,
            String realm,
            String realmDisplayName,
            String username,
            String email,
            String providerKey,
            String providerLabel,
            AuthProviderType providerType,
            int providerOrder) {
    }

    record ResolvedUserProvider(
            long id,
            String realm,
            String realmDisplayName,
            long userId,
            String username,
            String email,
            String providerKey,
            String providerLabel,
            AuthProviderType providerType,
            List<String> acls) {
    }
}
