package org.chenile.security.auth.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.chenile.security.auth.framework.contract.AuthProviderType;
import org.chenile.security.auth.framework.contract.ExternalProviderService;
import org.chenile.security.auth.framework.contract.MfaChallengeService;
import org.chenile.security.auth.framework.contract.MfaPolicyService;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.server.config.AuthServerProperties;
import org.chenile.security.auth.server.service.TokenService;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

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

    @Autowired
    private LoginFlowController controller;

    @Autowired
    private TokenService tokenService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    void passwordLoginWithoutMfaReturnsToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login/authenticate")
                        .contentType("application/json")
                        .content("""
                                {"email":"bob@example.test","providerId":2,"credential":"password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.authentication.mfa").value(false))
                .andReturn();

        String token = value(result, "accessToken");
        JWTClaimsSet claims = tokenService.verifiedClaims(token);
        assertThat(claims.getBooleanClaim("mfa")).isFalse();
        assertThat(claims.getStringListClaim("amr")).containsExactly("pwd");
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
                .andExpect(jsonPath("$.accessToken").doesNotExist());
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
                .andReturn();

        String token = value(result, "accessToken");
        JWTClaimsSet claims = tokenService.verifiedClaims(token);
        assertThat(claims.getBooleanClaim("mfa")).isTrue();
        assertThat(claims.getStringClaim("mfa_provider")).isEqualTo("email-otp");
        assertThat(claims.getStringListClaim("amr")).containsExactly("pwd", "otp");
    }

    @Test
    void wrongMfaCodeIsRejected() throws Exception {
        mockMvc.perform(post("/api/login/mfa/verify")
                        .contentType("application/json")
                        .content("""
                                {"challengeId":"challenge-alice","code":"wrong"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid MFA code"));
    }

    private String value(MvcResult result, String key) throws Exception {
        String body = result.getResponse().getContentAsString();
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("\"" + key + "\":\"([^\"]+)\"")
                .matcher(body);
        if (!matcher.find()) {
            throw new AssertionError("Missing JSON key " + key + " in " + body);
        }
        return matcher.group(1);
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
                    return "password".equals(rawPassword);
                }

                public boolean matchesClientSecret(ClientDefinition client, String rawSecret) {
                    return true;
                }

                public List<String> allowedScopes(String tenant, String clientId, List<String> requestedScopes) {
                    return requestedScopes;
                }

                public List<AuthProviderDefinition> providersForEmail(String email) {
                    return List.of();
                }

                public ResolvedUserProvider resolvedProvider(long providerId, String email) {
                    String realm = providerId == 1 ? "tenant-alpha" : "tenant-beta";
                    String username = providerId == 1 ? "alice" : "bob";
                    return new ResolvedUserProvider(
                            providerId,
                            realm,
                            realm,
                            providerId,
                            username,
                            email,
                            "local-password",
                            "Password",
                            AuthProviderType.PASSWORD,
                            List.of("role:user"));
                }

                public boolean authenticate(long providerId, String email, String secret) {
                    return "password".equals(secret);
                }

                public List<String> defaultBrowserScopes() {
                    return List.of("gateway.access");
                }

                public Map<String, Object> createRealmPayload(String tenant) {
                    return Map.of("realm", tenant);
                }
            };
        }

        @Bean
        ExternalProviderService externalProviderService() {
            return (realm, providerKey, providerType) -> null;
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
                        TenantRegistry.ResolvedUserProvider primaryProvider,
                        String clientId,
                        AuthProviderType primaryProviderType,
                        MfaPolicyService.MfaPolicy policy) {
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
                        throw new org.springframework.web.server.ResponseStatusException(
                                org.springframework.http.HttpStatus.UNAUTHORIZED,
                                "Invalid MFA code");
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
