package org.chenile.security.auth.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
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
                LoginFlowMfaIntegrationTest.TestConfig.class
        },
        properties = {
                "chenile.security.auth-server.token.audiences.gateway.access=gateway",
                "chenile.security.issuer-base=http://localhost:9000"
        })
class LoginFlowMfaIntegrationTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private LoginFlowController controller;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private MfaRecorder recorder;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        recorder.reset();
        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void identifyNormalizesEmailAndReturnsAvailableProviders() throws Exception {
        mockMvc.perform(post("/api/login/identify")
                        .contentType("application/json")
                        .content("""
                                {"email":"  ALICE@EXAMPLE.TEST  "}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.test"))
                .andExpect(jsonPath("$.tenant.realm").value("tenant-alpha"))
                .andExpect(jsonPath("$.providers.length()").value(2))
                .andExpect(jsonPath("$.providers[0].providerType").value("PASSWORD"))
                .andExpect(jsonPath("$.providers[1].providerType").value("GOOGLE"))
                .andExpect(jsonPath("$.nextStep").value("select-provider"))
                .andExpect(jsonPath("$.autoSelectedProviderId").doesNotExist());
    }

    @Test
    void identifyAutoSelectsSingleProvider() throws Exception {
        mockMvc.perform(post("/api/login/identify")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providers.length()").value(1))
                .andExpect(jsonPath("$.nextStep").value("authenticate"))
                .andExpect(jsonPath("$.autoSelectedProviderId").value(2));
    }

    @Test
    void identifyRejectsUnknownAndBlankEmail() throws Exception {
        mockMvc.perform(post("/api/login/identify")
                        .contentType("application/json")
                        .content("""
                                {"email":"unknown@example.test"}
                                """))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("No active authentication flow found for that email"));

        mockMvc.perform(post("/api/login/identify")
                        .contentType("application/json")
                        .content("""
                                {"email":" "}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("email is required"));
    }

    @Test
    void passwordLoginWithoutMfaReturnsTokenWithPasswordAmr() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":2,"credential":"password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.authentication.mfa").value(false))
                .andExpect(jsonPath("$.authentication.amr[0]").value("pwd"))
                .andReturn();

        JWTClaimsSet claims = tokenService.verifiedClaims(jsonValue(result, "accessToken"));
        assertThat(claims.getBooleanClaim("mfa")).isFalse();
        assertThat(claims.getStringListClaim("amr")).containsExactly("pwd");
        assertThat(claims.getStringClaim("auth_provider")).isEqualTo("local-password");
        assertThat(claims.getStringClaim("auth_provider_type")).isEqualTo("PASSWORD");
        assertThat(claims.getAudience()).containsExactly("gateway");
        assertThat(recorder.lastPolicyProviderType()).isEqualTo(AuthProviderType.PASSWORD);
    }

    @Test
    void otpPrimaryLoginWithoutMfaPreservesOtpProviderTypeAndAmr() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":3,"credential":"246810"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.authentication.provider.providerType").value("OTP"))
                .andExpect(jsonPath("$.authentication.amr[0]").value("otp"))
                .andReturn();

        JWTClaimsSet claims = tokenService.verifiedClaims(jsonValue(result, "accessToken"));
        assertThat(claims.getStringClaim("auth_provider_type")).isEqualTo("OTP");
        assertThat(claims.getStringListClaim("amr")).containsExactly("otp");
        assertThat(recorder.lastPolicyProviderType()).isEqualTo(AuthProviderType.OTP);
    }

    @Test
    void passwordLoginWithMfaReturnsChallengeAndNoToken() throws Exception {
        mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"alice@example.test","providerId":1,"credential":"password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nextStep").value("mfa"))
                .andExpect(jsonPath("$.challengeId").value("challenge-alice"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.provider.providerKey").value("email-otp"))
                .andExpect(jsonPath("$.provider.providerType").value("OTP"))
                .andExpect(jsonPath("$.tenant.realm").value("tenant-alpha"))
                .andExpect(jsonPath("$.user.username").value("alice"))
                .andExpect(jsonPath("$.authentication.provider.providerType").value("PASSWORD"));

        assertThat(recorder.lastPolicyProviderType()).isEqualTo(AuthProviderType.PASSWORD);
        assertThat(recorder.lastChallengeProviderType()).isEqualTo(AuthProviderType.PASSWORD);
        assertThat(recorder.lastChallengeClientId()).isEqualTo("browser-login");
    }

    @Test
    void correctMfaCodeReturnsTokenWithMfaClaims() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"challengeId":"challenge-alice","code":"246810"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.authentication.mfa").value(true))
                .andExpect(jsonPath("$.authentication.amr[0]").value("pwd"))
                .andExpect(jsonPath("$.authentication.amr[1]").value("otp"))
                .andReturn();

        JWTClaimsSet claims = tokenService.verifiedClaims(jsonValue(result, "accessToken"));
        assertThat(claims.getBooleanClaim("mfa")).isTrue();
        assertThat(claims.getStringClaim("mfa_provider")).isEqualTo("email-otp");
        assertThat(claims.getStringClaim("mfa_provider_type")).isEqualTo("OTP");
        assertThat(claims.getStringListClaim("amr")).containsExactly("pwd", "otp");
        assertThat(claims.getStringClaim("auth_provider")).isEqualTo("local-password");
        assertThat(claims.getStringClaim("auth_provider_type")).isEqualTo("PASSWORD");
    }

    @Test
    void serviceMeReturnsMfaAndAccessContextFromVerifiedToken() throws Exception {
        MvcResult login = mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"challengeId":"challenge-alice","code":"246810"}
                                """))
                .andExpect(status().isOk())
                .andReturn();

        mockMvc.perform(get("/api/service/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jsonValue(login, "accessToken")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant.realm").value("tenant-alpha"))
                .andExpect(jsonPath("$.user.username").value("alice"))
                .andExpect(jsonPath("$.authentication.providerKey").value("local-password"))
                .andExpect(jsonPath("$.authentication.providerType").value("PASSWORD"))
                .andExpect(jsonPath("$.authentication.mfa").value(true))
                .andExpect(jsonPath("$.authentication.amr[0]").value("pwd"))
                .andExpect(jsonPath("$.authentication.amr[1]").value("otp"))
                .andExpect(jsonPath("$.access.scopes[0]").value("gateway.access"))
                .andExpect(jsonPath("$.access.roles[0]").value("role:user"));
    }

    @Test
    void mfaVerifyRejectsMissingFieldsAndWrongCode() throws Exception {
        mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"code":"246810"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("challengeId is required"));

        mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"challengeId":"challenge-alice","code":" "}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("code is required"));

        mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"challengeId":"challenge-alice","code":"wrong"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid MFA code"));
    }

    @Test
    void authenticateRejectsInvalidInputsAndGoogleProvider() throws Exception {
        mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","credential":"password"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("providerId is required"));

        mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":2,"credential":" "}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("credential is required"));

        mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":2,"credential":"wrong"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Authentication failed"));

        mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"alice@example.test","providerId":4,"credential":"anything"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Google provider uses /api/login/google/start"));
    }

    @Test
    void serviceMeRejectsMissingBearerToken() throws Exception {
        mockMvc.perform(get("/api/service/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Bearer token is required"));
    }

    private String jsonValue(MvcResult result, String key) throws Exception {
        JsonNode node = OBJECT_MAPPER.readTree(result.getResponse().getContentAsString());
        assertThat(node.hasNonNull(key)).as("response has key %s: %s", key, node).isTrue();
        return node.get(key).asText();
    }

    static class MfaRecorder {
        private final AtomicReference<AuthProviderType> lastPolicyProviderType = new AtomicReference<>();
        private final AtomicReference<AuthProviderType> lastChallengeProviderType = new AtomicReference<>();
        private final AtomicReference<String> lastChallengeClientId = new AtomicReference<>();

        void recordPolicy(AuthProviderType providerType) {
            lastPolicyProviderType.set(providerType);
        }

        void recordChallenge(AuthProviderType providerType, String clientId) {
            lastChallengeProviderType.set(providerType);
            lastChallengeClientId.set(clientId);
        }

        AuthProviderType lastPolicyProviderType() {
            return lastPolicyProviderType.get();
        }

        AuthProviderType lastChallengeProviderType() {
            return lastChallengeProviderType.get();
        }

        String lastChallengeClientId() {
            return lastChallengeClientId.get();
        }

        void reset() {
            lastPolicyProviderType.set(null);
            lastChallengeProviderType.set(null);
            lastChallengeClientId.set(null);
        }
    }

    @TestConfiguration
    @EnableConfigurationProperties(AuthServerProperties.class)
    static class TestConfig {

        @Bean
        RestClient.Builder restClientBuilder() {
            return RestClient.builder();
        }

        @Bean
        MfaRecorder mfaRecorder() {
            return new MfaRecorder();
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
                    String email = username + "@example.test";
                    if ("alice".equals(username)) {
                        email = "alice@example.test";
                    } else if ("bob".equals(username)) {
                        email = "bob@example.test";
                    }
                    return new UserDefinition(1, tenant, username, email, "password", List.of("role:user"));
                }

                public boolean matchesUserPassword(UserDefinition user, String rawPassword) {
                    return "password".equals(rawPassword);
                }

                public boolean matchesClientSecret(ClientDefinition client, String rawSecret) {
                    return true;
                }

                public List<String> allowedScopes(String tenant, String clientId, List<String> requestedScopes) {
                    return requestedScopes;
                }

                public List<AuthProviderDefinition> providersForEmail(String email) {
                    return switch (email) {
                        case "alice@example.test" -> List.of(
                                provider(1, "tenant-alpha", "alice", email, "local-password", "Password", AuthProviderType.PASSWORD),
                                provider(4, "tenant-alpha", "alice", email, "google", "Google", AuthProviderType.GOOGLE));
                        case "bob@example.test" -> List.of(
                                provider(2, "tenant-beta", "bob", email, "local-password", "Password", AuthProviderType.PASSWORD));
                        default -> List.of();
                    };
                }

                public ResolvedUserProvider resolvedProvider(long providerId, String email) {
                    return switch ((int) providerId) {
                        case 1 -> resolved(1, "tenant-alpha", "alice", "alice@example.test", "local-password", "Password", AuthProviderType.PASSWORD);
                        case 2 -> resolved(2, "tenant-beta", "bob", "bob@example.test", "local-password", "Password", AuthProviderType.PASSWORD);
                        case 3 -> resolved(3, "tenant-beta", "bob", "bob@example.test", "login-otp", "Login OTP", AuthProviderType.OTP);
                        case 4 -> resolved(4, "tenant-alpha", "alice", "alice@example.test", "google", "Google", AuthProviderType.GOOGLE);
                        default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Provider not found");
                    };
                }

                public boolean authenticate(long providerId, String email, String secret) {
                    if (providerId == 3) {
                        return "246810".equals(secret);
                    }
                    return "password".equals(secret);
                }

                public List<String> defaultBrowserScopes() {
                    return List.of("gateway.access");
                }

                public Map<String, Object> createRealmPayload(String tenant) {
                    return Map.of("realm", tenant);
                }

                private AuthProviderDefinition provider(
                        long id,
                        String realm,
                        String username,
                        String email,
                        String providerKey,
                        String providerLabel,
                        AuthProviderType providerType) {
                    return new AuthProviderDefinition(
                            id,
                            realm,
                            realm,
                            username,
                            email,
                            providerKey,
                            providerLabel,
                            providerType,
                            (int) id);
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
            return (realm, providerKey, providerType) -> null;
        }

        @Bean
        MfaPolicyService mfaPolicyService(MfaRecorder recorder) {
            return (primaryProvider, clientId, primaryProviderType) -> {
                recorder.recordPolicy(primaryProviderType);
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
        MfaChallengeService mfaChallengeService(MfaRecorder recorder) {
            return new MfaChallengeService() {
                public MfaChallenge start(
                        ResolvedUserProvider primaryProvider,
                        String clientId,
                        AuthProviderType primaryProviderType,
                        MfaPolicyService.MfaPolicy policy) {
                    recorder.recordChallenge(primaryProviderType, clientId);
                    return new MfaChallenge(
                            "challenge-alice",
                            policy.providerKey(),
                            policy.providerType(),
                            policy.displayName(),
                            policy.destinationHint(),
                            Instant.now().plus(policy.challengeTtl()));
                }

                public VerifiedMfaChallenge verify(String challengeId, String code) {
                    if (!"challenge-alice".equals(challengeId) || !"246810".equals(code)) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid MFA code");
                    }
                    return new VerifiedMfaChallenge(
                            challengeId,
                            "tenant-alpha",
                            "alice@example.test",
                            1,
                            "browser-login",
                            AuthProviderType.PASSWORD,
                            "email-otp",
                            AuthProviderType.OTP);
                }
            };
        }
    }
}
