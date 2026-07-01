package org.chenile.security.auth.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.server.config.AuthServerProperties;
import org.chenile.security.auth.server.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@SpringBootTest(
        classes = {
                AuthController.class,
                TokenService.class,
                AuthControllerIntegrationTest.TestConfig.class
        },
        properties = {
                "chenile.security.issuer-base=http://localhost:9000",
                "chenile.security.auth-server.token.audiences.gateway.access=gateway",
                "chenile.security.auth-server.token.audiences.service-a.read=service-a"
        })
class AuthControllerIntegrationTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private AuthController controller;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private InMemoryTenantRegistry tenantRegistry;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        tenantRegistry.reset();
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void openIdConfigurationAndJwksAreExposedForKnownRealm() throws Exception {
        mockMvc.perform(get("/realms/tenant-alpha/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:9000/realms/tenant-alpha"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:9000/realms/tenant-alpha/protocol/openid-connect/certs"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:9000/realms/tenant-alpha/protocol/openid-connect/token"))
                .andExpect(jsonPath("$.grant_types_supported[0]").value("client_credentials"))
                .andExpect(jsonPath("$.grant_types_supported[1]").value("password"));

        mockMvc.perform(get("/realms/tenant-alpha/protocol/openid-connect/certs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").exists());
    }

    @Test
    void openIdConfigurationRejectsUnknownRealm() throws Exception {
        mockMvc.perform(get("/realms/missing/.well-known/openid-configuration"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Unknown realm missing"));
    }

    @Test
    void clientCredentialsGrantIssuesClientTokenWithAllowedScopes() throws Exception {
        MvcResult result = mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, basic("service-client", "secret"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "gateway.access service-a.read unknown.scope"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.scope").value("gateway.access service-a.read"))
                .andReturn();

        JWTClaimsSet claims = tokenService.verifiedClaims(jsonValue(result, "access_token"));
        assertThat(claims.getStringClaim("tenant")).isEqualTo("tenant-alpha");
        assertThat(claims.getSubject()).isEqualTo("service-client");
        assertThat(claims.getAudience()).containsExactlyInAnyOrder("gateway", "service-a");
    }

    @Test
    void passwordGrantIssuesUserTokenWithAcls() throws Exception {
        MvcResult result = mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("client_id", "browser-login")
                        .param("username", "alice")
                        .param("password", "password")
                        .param("scope", "gateway.access"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("gateway.access"))
                .andReturn();

        JWTClaimsSet claims = tokenService.verifiedClaims(jsonValue(result, "access_token"));
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getStringListClaim("roles")).containsExactly("orders:read");
        assertThat(claims.getStringClaim("azp")).isEqualTo("browser-login");
    }

    @Test
    void tokenEndpointRejectsInvalidRequests() throws Exception {
        mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", "browser-login"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Missing grant_type"));

        mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("client_id", "browser-login"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unsupported grant type refresh_token"));

        mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, basic("service-client", "wrong"))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid client credentials"));

        mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("client_id", "service-client")
                        .param("client_secret", "secret")
                        .param("username", "alice")
                        .param("password", "password"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Password grant is disabled"));

        mockMvc.perform(post("/realms/tenant-alpha/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("client_id", "browser-login")
                        .param("username", "alice")
                        .param("password", "wrong"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid user credentials"));
    }

    @Test
    void adminEndpointsCreateRealmAndClientWithAdminToken() throws Exception {
        String adminToken = tokenService.issueUserToken(
                "platform",
                "admin-cli",
                "admin",
                List.of(),
                List.of("iam:admin"));

        mockMvc.perform(post("/admin/realms")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"realm":"tenant-gamma"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.realm").value("tenant-gamma"));

        mockMvc.perform(post("/admin/realms")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"realm":"tenant-gamma"}
                                """))
                .andExpect(status().isConflict());

        mockMvc.perform(post("/admin/realms/tenant-gamma/clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"clientId":"new-service","secret":"new-secret","optionalClientScopes":["gateway.access"]}
                                """))
                .andExpect(status().isCreated())
                .andExpect(header().string(HttpHeaders.LOCATION, "/admin/realms/tenant-gamma/clients/new-service"))
                .andExpect(jsonPath("$.clientId").value("new-service"));
    }

    @Test
    void adminEndpointsRejectInvalidTokenAndInvalidPayload() throws Exception {
        String nonAdminToken = tokenService.issueUserToken(
                "tenant-alpha",
                "browser-login",
                "alice",
                List.of("gateway.access"),
                List.of("orders:read"));

        mockMvc.perform(post("/admin/realms")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + nonAdminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"realm":"tenant-gamma"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid admin token"));

        String adminToken = tokenService.issueUserToken(
                "platform",
                "admin-cli",
                "admin",
                List.of(),
                List.of("iam:admin"));

        mockMvc.perform(post("/admin/realms")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"realm":" "}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("realm is required"));

        mockMvc.perform(post("/admin/realms/tenant-alpha/clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"clientId":" "}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("clientId is required"));
    }

    private String jsonValue(MvcResult result, String key) throws Exception {
        JsonNode node = OBJECT_MAPPER.readTree(result.getResponse().getContentAsString());
        assertThat(node.hasNonNull(key)).as("response has key %s: %s", key, node).isTrue();
        return node.get(key).asText();
    }

    private String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @TestConfiguration
    @EnableConfigurationProperties(AuthServerProperties.class)
    static class TestConfig {

        @Bean
        InMemoryTenantRegistry tenantRegistry() {
            return new InMemoryTenantRegistry();
        }
    }

    static class InMemoryTenantRegistry implements TenantRegistry {

        private final Map<String, Boolean> realms = new LinkedHashMap<>();
        private final Map<String, ClientDefinition> clients = new LinkedHashMap<>();

        void reset() {
            realms.clear();
            realms.put("tenant-alpha", true);
            realms.put("platform", true);
            clients.clear();
            clients.put(key("tenant-alpha", "service-client"), new ClientDefinition(
                    "service-client", "secret", true, false, List.of("gateway.access", "service-a.read")));
            clients.put(key("tenant-alpha", "browser-login"), new ClientDefinition(
                    "browser-login", null, false, true, List.of("gateway.access")));
            clients.put(key("platform", "admin-cli"), new ClientDefinition(
                    "admin-cli", null, false, false, List.of()));
        }

        public RealmDefinition realm(String tenant) {
            return new RealmDefinition(1, tenant, tenant);
        }

        public boolean realmExists(String tenant) {
            return realms.containsKey(tenant);
        }

        public boolean createRealm(String tenant) {
            if (realms.containsKey(tenant)) {
                return false;
            }
            realms.put(tenant, true);
            return true;
        }

        public void registerClient(String tenant, ClientDefinition client) {
            clients.put(key(tenant, client.clientId()), client);
        }

        public ClientDefinition client(String tenant, String clientId) {
            ClientDefinition client = clients.get(key(tenant, clientId));
            if (client == null) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unknown client");
            }
            return client;
        }

        public UserDefinition user(String tenant, String username) {
            return new UserDefinition(1, tenant, username, username + "@example.test", "password", List.of("orders:read"));
        }

        public boolean matchesUserPassword(UserDefinition user, String rawPassword) {
            return user.passwordSecretHash().equals(rawPassword);
        }

        public boolean matchesClientSecret(ClientDefinition client, String rawSecret) {
            return client.secret() != null && client.secret().equals(rawSecret);
        }

        public List<String> allowedScopes(String tenant, String clientId, List<String> requestedScopes) {
            ClientDefinition client = client(tenant, clientId);
            return requestedScopes.stream()
                    .filter(client.allowedScopes()::contains)
                    .toList();
        }

        public List<AuthProviderDefinition> providersForEmail(String email) {
            return List.of();
        }

        public ResolvedUserProvider resolvedProvider(long providerId, String email) {
            throw new UnsupportedOperationException();
        }

        public boolean authenticate(long providerId, String email, String secret) {
            return false;
        }

        public List<String> defaultBrowserScopes() {
            return List.of("gateway.access");
        }

        public Map<String, Object> createRealmPayload(String tenant) {
            return Map.of("realm", tenant);
        }

        private String key(String tenant, String clientId) {
            return tenant + "/" + clientId;
        }
    }
}
