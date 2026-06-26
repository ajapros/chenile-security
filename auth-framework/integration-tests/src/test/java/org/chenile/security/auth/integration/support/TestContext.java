package org.chenile.security.auth.integration.support;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.opentest4j.TestAbortedException;
import org.testcontainers.DockerClientFactory;

public class TestContext {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private HttpResponse<String> lastResponse;
    private Map<String, Object> lastJson;
    private String accessToken;
    private String adminAccessToken;
    private final Map<String, String> clientRealms = new HashMap<>(Map.of("system-client", "platform"));
    private final Map<String, String> userRealms = Map.of(
            "alice", "tenant-alpha",
            "bob", "tenant-beta",
            "ops-admin", "platform");
    private final Set<String> knownRealms = java.util.Collections.synchronizedSet(
            new java.util.HashSet<>(Set.of("tenant-alpha", "tenant-beta", "platform")));

    public void ensureEnvironmentStarted() {
        if (!DockerClientFactory.instance().isDockerAvailable()) {
            throw new TestAbortedException("Docker is required for the Cucumber integration suite");
        }
        IntegrationEnvironment.gatewayBaseUrl();
    }

    public void requestOpenIdConfiguration() throws IOException, InterruptedException {
        lastResponse = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl()
                        + "/realms/tenant-alpha/.well-known/openid-configuration"))
                .GET()
                .build());
        parseLastJson();
    }

    public void requestClientCredentialsToken(String clientId, String clientSecret, String scope)
            throws IOException, InterruptedException {
        String basicAuth = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        String realm = realmForClient(clientId);
        String body = "grant_type=client_credentials&scope="
                + URLEncoder.encode(scope, StandardCharsets.UTF_8);
        lastResponse = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl()
                        + "/realms/" + realm + "/protocol/openid-connect/token"))
                .header("Authorization", "Basic " + basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        parseLastJson();
        if (lastJson != null && lastJson.containsKey("access_token")) {
            accessToken = String.valueOf(lastJson.get("access_token"));
        }
    }

    public void requestPasswordToken(String username, String password, String clientId, String clientSecret, String scope)
            throws IOException, InterruptedException {
        String basicAuth = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        String realm = realmForUser(username);
        String body = "grant_type=password&username="
                + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password="
                + URLEncoder.encode(password, StandardCharsets.UTF_8)
                + "&scope="
                + URLEncoder.encode(scope, StandardCharsets.UTF_8);
        lastResponse = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl()
                        + "/realms/" + realm + "/protocol/openid-connect/token"))
                .header("Authorization", "Basic " + basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        parseLastJson();
        if (lastJson != null && lastJson.containsKey("access_token")) {
            accessToken = String.valueOf(lastJson.get("access_token"));
        }
    }

    public void registerClient(String clientId, String clientSecret, String tenantId, String scope)
            throws IOException, InterruptedException {
        ensureAdminAccessToken();
        ensureRealmExists(tenantId);
        List<String> scopes = List.of(scope.split(" "));
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("clientId", clientId);
        client.put("name", clientId);
        client.put("protocol", "openid-connect");
        client.put("publicClient", false);
        client.put("secret", clientSecret);
        client.put("standardFlowEnabled", false);
        client.put("directAccessGrantsEnabled", false);
        client.put("serviceAccountsEnabled", true);
        client.put("fullScopeAllowed", false);
        client.put("optionalClientScopes", scopes);
        String body = objectMapper.writeValueAsString(client);
        lastResponse = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl() + "/admin/realms/" + tenantId + "/clients"))
                .header("Authorization", "Bearer " + adminAccessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        parseLastJson();
        if (lastStatusCode() == 201) {
            clientRealms.put(clientId, tenantId);
        }
    }

    public void callPublicGateway(String path) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.gatewayBaseUrl() + path))
                .GET();
        if (accessToken != null) {
            builder.header("Authorization", "Bearer " + accessToken);
        }
        lastResponse = send(builder.build());
        parseLastJson();
    }

    public void postAuthServerJson(String path, String body) throws IOException, InterruptedException {
        lastResponse = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl() + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        parseLastJson();
    }

    public int lastStatusCode() {
        return lastResponse.statusCode();
    }

    public String lastBody() {
        return lastResponse.body();
    }

    public Object jsonField(String field) {
        if (lastJson == null) {
            return null;
        }
        Object current = lastJson;
        for (String part : field.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = map.get(part);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private void ensureAdminAccessToken() throws IOException, InterruptedException {
        if (adminAccessToken != null) {
            return;
        }
        String body = "client_id=admin-cli&grant_type=password&username="
                + URLEncoder.encode("admin", StandardCharsets.UTF_8)
                + "&password="
                + URLEncoder.encode("admin", StandardCharsets.UTF_8);
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl()
                        + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        lastResponse = response;
        parseLastJson();
        adminAccessToken = String.valueOf(lastJson.get("access_token"));
    }

    private String realmForClient(String clientId) {
        return clientRealms.getOrDefault(clientId, "platform");
    }

    private String realmForUser(String username) {
        return userRealms.getOrDefault(username, "platform");
    }

    private void ensureRealmExists(String realmName) throws IOException, InterruptedException {
        if (knownRealms.contains(realmName)) {
            return;
        }
        Map<String, Object> realm = new LinkedHashMap<>();
        realm.put("realm", realmName);
        realm.put("enabled", true);
        realm.put("registrationAllowed", false);
        realm.put("loginWithEmailAllowed", true);
        realm.put("duplicateEmailsAllowed", false);
        realm.put("resetPasswordAllowed", true);
        realm.put("roles", Map.of("realm", List.of()));
        realm.put("clientScopes", List.of(
                audienceScope("gateway.access", "gateway"),
                audienceScope("service-a.read", "service-a"),
                audienceScope("service-b.read", "service-b"),
                userIdScope(),
                rolesScope(),
                aclsScope()));
        String body = objectMapper.writeValueAsString(realm);
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(IntegrationEnvironment.authServerBaseUrl() + "/admin/realms"))
                .header("Authorization", "Bearer " + adminAccessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build());
        lastResponse = response;
        parseLastJson();
        if (response.statusCode() == 201 || response.statusCode() == 409) {
            knownRealms.add(realmName);
            return;
        }
        throw new IllegalStateException("Failed to create realm " + realmName + ": " + response.body());
    }

    private Map<String, Object> audienceScope(String name, String audience) {
        return Map.of(
                "name", name,
                "protocol", "openid-connect",
                "attributes", Map.of("include.in.token.scope", "true"),
                "protocolMappers", List.of(Map.of(
                        "name", name + "-audience",
                        "protocol", "openid-connect",
                        "protocolMapper", "oidc-audience-mapper",
                        "consentRequired", false,
                        "config", Map.of(
                                "included.client.audience", audience,
                                "access.token.claim", "true",
                                "id.token.claim", "false"))));
    }

    private Map<String, Object> userIdScope() {
        return Map.of(
                "name", "user-id",
                "protocol", "openid-connect",
                "protocolMappers", List.of(Map.of(
                        "name", "user-id",
                        "protocol", "openid-connect",
                        "protocolMapper", "oidc-usermodel-property-mapper",
                        "consentRequired", false,
                        "config", Map.of(
                                "user.attribute", "username",
                                "claim.name", "user_id",
                                "jsonType.label", "String",
                                "access.token.claim", "true",
                                "id.token.claim", "true",
                                "userinfo.token.claim", "true"))));
    }

    private Map<String, Object> rolesScope() {
        return Map.of(
                "name", "roles",
                "protocol", "openid-connect",
                "protocolMappers", List.of(Map.of(
                        "name", "roles",
                        "protocol", "openid-connect",
                        "protocolMapper", "oidc-usermodel-realm-role-mapper",
                        "consentRequired", false,
                        "config", Map.of(
                                "claim.name", "roles",
                                "jsonType.label", "String",
                                "multivalued", "true",
                                "access.token.claim", "true",
                                "id.token.claim", "true",
                                "userinfo.token.claim", "true"))));
    }

    private Map<String, Object> aclsScope() {
        return Map.of(
                "name", "acls",
                "protocol", "openid-connect",
                "protocolMappers", List.of(Map.of(
                        "name", "acls",
                        "protocol", "openid-connect",
                        "protocolMapper", "oidc-usermodel-realm-role-mapper",
                        "consentRequired", false,
                        "config", Map.of(
                                "claim.name", "acls",
                                "jsonType.label", "String",
                                "multivalued", "true",
                                "access.token.claim", "true",
                                "id.token.claim", "true",
                                "userinfo.token.claim", "true"))));
    }

    private void parseLastJson() throws IOException {
        String body = lastResponse.body();
        if (body == null || body.isBlank() || !body.trim().startsWith("{")) {
            lastJson = null;
            return;
        }
        lastJson = objectMapper.readValue(body, new TypeReference<>() {
        });
    }
}
