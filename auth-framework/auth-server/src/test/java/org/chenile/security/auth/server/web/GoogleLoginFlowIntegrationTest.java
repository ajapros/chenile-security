package org.chenile.security.auth.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.chenile.security.auth.framework.contract.AuthProviderType;
import org.chenile.security.auth.framework.contract.ExternalProviderService;
import org.chenile.security.auth.framework.contract.MfaChallengeService;
import org.chenile.security.auth.framework.contract.MfaPolicyService;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;
import org.chenile.security.auth.server.config.AuthServerProperties;
import org.chenile.security.auth.server.service.TokenService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@SpringBootTest(
        classes = {
                LoginFlowController.class,
                TokenService.class,
                GoogleLoginFlowIntegrationTest.TestConfig.class
        },
        properties = {
                "chenile.security.auth-server.token.audiences.gateway.access=gateway",
                "chenile.security.issuer-base=http://localhost:9000",
                "chenile.security.demo-ui.success-uri=http://localhost:5173/"
        })
class GoogleLoginFlowIntegrationTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final AtomicReference<String> USER_INFO_EMAIL = new AtomicReference<>("bob@example.test");
    private static HttpServer server;
    private static String serverBaseUrl;

    @Autowired
    private LoginFlowController controller;

    private MockMvc mockMvc;

    @BeforeAll
    static void startProviderServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/token", exchange -> {
            byte[] body = """
                    {"access_token":"external-token","token_type":"Bearer"}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream response = exchange.getResponseBody()) {
                response.write(body);
            }
        });
        server.createContext("/userinfo", exchange -> {
            byte[] body = ("""
                    {"email":"%s"}
                    """.formatted(USER_INFO_EMAIL.get())).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream response = exchange.getResponseBody()) {
                response.write(body);
            }
        });
        server.start();
        serverBaseUrl = "http://localhost:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopProviderServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @BeforeEach
    void setUp() {
        USER_INFO_EMAIL.set("bob@example.test");
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void googleStartBuildsAuthorizationUrlAndStoresSessionState() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login/google/start")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":5}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.provider.providerType").value("GOOGLE"))
                .andExpect(jsonPath("$.redirectUrl").value(org.hamcrest.Matchers.containsString(serverBaseUrl + "/authorize")))
                .andReturn();

        String redirectUrl = OBJECT_MAPPER.readTree(result.getResponse().getContentAsString())
                .get("redirectUrl")
                .asText();
        assertThat(queryParam(redirectUrl, "client_id")).isEqualTo("google-client");
        assertThat(queryParam(redirectUrl, "redirect_uri")).isEqualTo("http://localhost:9000/api/login/google/callback");
        assertThat(queryParam(redirectUrl, "state")).isNotBlank();
        assertThat(result.getRequest().getSession(false)).isNotNull();
    }

    @Test
    void googleStartRejectsNonGoogleProviderAndIncompleteConfig() throws Exception {
        mockMvc.perform(post("/api/login/google/start")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":2}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Selected provider is not Google"));

        mockMvc.perform(post("/api/login/google/start")
                        .contentType("application/json")
                        .content("""
                                {"email":"config-broken@example.test","providerId":6}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Provider config is incomplete in DB for tenant-beta/broken-google"));
    }

    @Test
    void googleCallbackRedirectsWithAccessTokenWhenMfaIsNotRequired() throws Exception {
        MvcResult start = startGoogle("bob@example.test", 5);
        String state = state(start);

        mockMvc.perform(get("/api/login/google/callback")
                        .session((MockHttpSession) start.getRequest().getSession(false))
                        .param("code", "code-ok")
                        .param("state", state))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, org.hamcrest.Matchers.startsWith("http://localhost:5173/#access_token=")));
    }

    @Test
    void googleCallbackRedirectsToMfaWhenTenantPolicyRequiresMfa() throws Exception {
        USER_INFO_EMAIL.set("alice@example.test");
        MvcResult start = startGoogle("alice@example.test", 4);

        mockMvc.perform(get("/api/login/google/callback")
                        .session((MockHttpSession) start.getRequest().getSession(false))
                        .param("code", "code-ok")
                        .param("state", state(start)))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, org.hamcrest.Matchers.allOf(
                        org.hamcrest.Matchers.containsString("#next_step=mfa"),
                        org.hamcrest.Matchers.containsString("challenge_id=google-challenge"),
                        org.hamcrest.Matchers.containsString("email=alice%40example.test"))));
    }

    @Test
    void googleCallbackRejectsMissingSessionWrongStateAndEmailMismatch() throws Exception {
        mockMvc.perform(get("/api/login/google/callback")
                        .param("code", "code-ok")
                        .param("state", "missing-session"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Missing external login session"));

        MvcResult start = startGoogle("bob@example.test", 5);
        mockMvc.perform(get("/api/login/google/callback")
                        .session((MockHttpSession) start.getRequest().getSession(false))
                        .param("code", "code-ok")
                        .param("state", "wrong"))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, "http://localhost:5173/#error=external_login_state_mismatch"));

        USER_INFO_EMAIL.set("other@example.test");
        mockMvc.perform(get("/api/login/google/callback")
                        .session((MockHttpSession) start.getRequest().getSession(false))
                        .param("code", "code-ok")
                        .param("state", state(start)))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, "http://localhost:5173/#error=google_email_mismatch"));
    }

    private MvcResult startGoogle(String email, long providerId) throws Exception {
        return mockMvc.perform(post("/api/login/google/start")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","providerId":%d}
                                """.formatted(email, providerId)))
                .andExpect(status().isOk())
                .andReturn();
    }

    private String state(MvcResult start) throws Exception {
        String redirectUrl = OBJECT_MAPPER.readTree(start.getResponse().getContentAsString())
                .get("redirectUrl")
                .asText();
        return queryParam(redirectUrl, "state");
    }

    private String queryParam(String url, String name) {
        String query = url.substring(url.indexOf('?') + 1);
        for (String part : query.split("&")) {
            String[] keyValue = part.split("=", 2);
            if (keyValue.length == 2 && keyValue[0].equals(name)) {
                return URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    @TestConfiguration
    @EnableConfigurationProperties(AuthServerProperties.class)
    static class TestConfig {

        @Bean
        RestClient.Builder restClientBuilder() {
            return RestClient.builder();
        }

        @Bean
        TenantRegistry tenantRegistry() {
            return new TenantRegistry() {
                public RealmDefinition realm(String tenant) {
                    return new RealmDefinition(1, tenant, tenant);
                }

                public boolean realmExists(String tenant) {
                    return true;
                }

                public boolean createRealm(String tenant) {
                    return true;
                }

                public void registerClient(String tenant, ClientDefinition client) {
                }

                public ClientDefinition client(String tenant, String clientId) {
                    return new ClientDefinition(clientId, null, false, false, List.of("gateway.access"));
                }

                public UserDefinition user(String tenant, String username) {
                    return new UserDefinition(1, tenant, username, username + "@example.test", "password", List.of("role:user"));
                }

                public boolean matchesUserPassword(UserDefinition user, String rawPassword) {
                    return false;
                }

                public boolean matchesClientSecret(ClientDefinition client, String rawSecret) {
                    return false;
                }

                public List<String> allowedScopes(String tenant, String clientId, List<String> requestedScopes) {
                    return requestedScopes;
                }

                public List<AuthProviderDefinition> providersForEmail(String email) {
                    return List.of();
                }

                public ResolvedUserProvider resolvedProvider(long providerId, String email) {
                    return switch ((int) providerId) {
                        case 2 -> resolved(2, "tenant-beta", "bob", "bob@example.test", "local-password", "Password", AuthProviderType.PASSWORD);
                        case 4 -> resolved(4, "tenant-alpha", "alice", "alice@example.test", "google", "Google", AuthProviderType.GOOGLE);
                        case 5 -> resolved(5, "tenant-beta", "bob", "bob@example.test", "google", "Google", AuthProviderType.GOOGLE);
                        case 6 -> resolved(6, "tenant-beta", "config-broken", "config-broken@example.test", "broken-google", "Broken Google", AuthProviderType.GOOGLE);
                        default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Provider not found");
                    };
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

                private ResolvedUserProvider resolved(
                        long id,
                        String realm,
                        String username,
                        String email,
                        String providerKey,
                        String providerLabel,
                        AuthProviderType providerType) {
                    return new ResolvedUserProvider(
                            id,
                            realm,
                            realm,
                            id,
                            username,
                            email,
                            providerKey,
                            providerLabel,
                            providerType,
                            List.of("role:user"));
                }
            };
        }

        @Bean
        ExternalProviderService externalProviderService() {
            return (realm, providerKey, providerType) -> {
                if ("broken-google".equals(providerKey)) {
                    return new ExternalProviderService.ProviderConfigDefinition(
                            realm,
                            providerKey,
                            providerType,
                            "SET_CLIENT_ID",
                            "SET_CLIENT_SECRET",
                            serverBaseUrl + "/authorize",
                            serverBaseUrl + "/token",
                            serverBaseUrl + "/userinfo",
                            List.of("openid", "email"));
                }
                return new ExternalProviderService.ProviderConfigDefinition(
                        realm,
                        providerKey,
                        providerType,
                        "google-client",
                        "google-secret",
                        serverBaseUrl + "/authorize",
                        serverBaseUrl + "/token",
                        serverBaseUrl + "/userinfo",
                        List.of("openid", "email"));
            };
        }

        @Bean
        MfaPolicyService mfaPolicyService() {
            return (primaryProvider, clientId, primaryProviderType) -> {
                if ("tenant-alpha".equals(primaryProvider.realm())) {
                    return new MfaPolicyService.MfaPolicy(
                            true,
                            "email-otp",
                            AuthProviderType.OTP,
                            "Email OTP",
                            "Seeded OTP",
                            Duration.ofMinutes(5),
                            List.of(AuthProviderType.OTP));
                }
                return MfaPolicyService.MfaPolicy.notRequired();
            };
        }

        @Bean
        MfaChallengeService mfaChallengeService() {
            return new MfaChallengeService() {
                public MfaChallenge start(
                        ResolvedUserProvider primaryProvider,
                        String clientId,
                        AuthProviderType primaryProviderType,
                        MfaPolicyService.MfaPolicy policy) {
                    return new MfaChallenge(
                            "google-challenge",
                            policy.providerKey(),
                            policy.providerType(),
                            policy.displayName(),
                            policy.destinationHint(),
                            Instant.now().plus(policy.challengeTtl()));
                }

                public VerifiedMfaChallenge verify(String challengeId, String code) {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }
}
