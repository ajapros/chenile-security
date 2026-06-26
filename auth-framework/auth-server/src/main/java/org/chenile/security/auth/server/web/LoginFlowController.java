package org.chenile.security.auth.server.web;

import org.chenile.security.auth.server.config.AuthServerProperties;
import org.chenile.security.auth.server.config.AuthServerProperties.ServiceDefinition;
import org.chenile.security.auth.server.service.TokenService;
import org.chenile.security.auth.framework.contract.AuthProviderType;
import org.chenile.security.auth.framework.contract.ExternalProviderService;
import org.chenile.security.auth.framework.contract.ExternalProviderService.ProviderConfigDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.framework.contract.TenantRegistry.AuthProviderDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry.ClientDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;
import org.chenile.security.auth.framework.contract.TenantRegistry.UserDefinition;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class LoginFlowController {

    private static final String PENDING_EXTERNAL_LOGIN = "pending-external-login";

    private final TenantRegistry tenantRegistry;
    private final ExternalProviderService externalProviderService;
    private final TokenService tokenService;
    private final AuthServerProperties properties;
    private final RestClient restClient;
    private final String authServerBaseUri;
    private final String successUri;

    public LoginFlowController(
            TenantRegistry tenantRegistry,
            ExternalProviderService externalProviderService,
            TokenService tokenService,
            AuthServerProperties properties,
            RestClient.Builder restClientBuilder,
            @Value("${chenile.security.issuer-base:http://localhost:9000}") String authServerBaseUri,
            @Value("${chenile.security.demo-ui.success-uri:http://localhost:5173/}") String successUri) {
        this.tenantRegistry = tenantRegistry;
        this.externalProviderService = externalProviderService;
        this.tokenService = tokenService;
        this.properties = properties;
        this.restClient = restClientBuilder.build();
        this.authServerBaseUri = authServerBaseUri;
        this.successUri = successUri;
    }

    @PostMapping("/login/identify")
    Map<String, Object> identify(@RequestBody IdentifyRequest request) {
        String email = normalizedEmail(request.email());
        List<AuthProviderDefinition> providers = tenantRegistry.providersForEmail(email);
        if (providers.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No active authentication flow found for that email");
        }

        AuthProviderDefinition primaryProvider = providers.getFirst();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("email", email);
        payload.put("tenant", Map.of(
                "realm", primaryProvider.realm(),
                "displayName", primaryProvider.realmDisplayName()));
        payload.put("providers", providers.stream().map(this::toProviderPayload).toList());
        payload.put("nextStep", providers.size() == 1 ? "authenticate" : "select-provider");
        payload.put("autoSelectedProviderId", providers.size() == 1 ? primaryProvider.id() : null);
        payload.put("credentialHints", credentialHints(email));
        return payload;
    }

    @PostMapping("/login/authenticate")
    Map<String, Object> authenticate(@RequestBody AuthenticateRequest request) {
        String email = normalizedEmail(request.email());
        if (request.providerId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "providerId is required");
        }
        ResolvedUserProvider provider = tenantRegistry.resolvedProvider(request.providerId(), email);
        if (provider.providerType() == AuthProviderType.GOOGLE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Google provider uses /api/login/google/start");
        }
        if (request.credential() == null || request.credential().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "credential is required");
        }
        boolean authenticated = tenantRegistry.authenticate(provider.id(), email, request.credential());
        if (!authenticated) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication failed");
        }

        List<String> scopes = tenantRegistry.defaultBrowserScopes();
        ClientDefinition client = tenantRegistry.client(provider.realm(), "browser-login");
        String accessToken = tokenService.issueUserToken(
                provider.realm(),
                "browser-login",
                provider.username(),
                scopes,
                provider.acls(),
                Map.of(
                        "auth_provider", provider.providerKey(),
                        "auth_provider_type", provider.providerType().name(),
                        "email", provider.email()));

        return new LinkedHashMap<>(Map.of(
                "generatedAt", Instant.now().toString(),
                "tokenType", "Bearer",
                "expiresIn", 600,
                "accessToken", accessToken,
                "tenant", Map.of(
                        "realm", provider.realm(),
                        "displayName", provider.realmDisplayName(),
                        "issuer", tokenService.issuer(provider.realm())),
                "user", Map.of(
                        "id", provider.userId(),
                        "username", provider.username(),
                        "email", provider.email()),
                "authentication", Map.of(
                        "clientId", client.clientId(),
                        "provider", toResolvedProviderPayload(provider),
                        "scopes", scopes,
                        "roles", provider.acls(),
                        "acls", provider.acls())));
    }

    @PostMapping("/login/google/start")
    Map<String, Object> startGoogleLogin(
            @RequestBody GoogleStartRequest request,
            HttpServletRequest httpRequest) {
        String email = normalizedEmail(request.email());
        if (request.providerId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "providerId is required");
        }
        ResolvedUserProvider provider = tenantRegistry.resolvedProvider(request.providerId(), email);
        if (provider.providerType() != AuthProviderType.GOOGLE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Selected provider is not Google");
        }
        ProviderConfigDefinition config = externalProviderService.providerConfig(
                provider.realm(),
                provider.providerKey(),
                provider.providerType());
        validateProviderConfig(config);

        String state = UUID.randomUUID().toString();
        httpRequest.getSession(true).setAttribute(
                PENDING_EXTERNAL_LOGIN,
                new PendingExternalLogin(email, provider.id(), provider.realm(), provider.providerKey(), state));
        return Map.of(
                "redirectUrl", buildAuthorizationUrl(config, state),
                "provider", toResolvedProviderPayload(provider));
    }

    @GetMapping("/login/google/callback")
    void googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            HttpServletRequest request,
            HttpServletResponse response) throws java.io.IOException {
        if (error != null) {
            redirect(response, failureUrl("google_authentication_failed"));
            return;
        }
        if (code == null || code.isBlank() || state == null || state.isBlank()) {
            redirect(response, failureUrl("missing_google_callback_parameters"));
            return;
        }

        PendingExternalLogin pending = pendingLogin(request);
        if (!pending.state().equals(state)) {
            redirect(response, failureUrl("external_login_state_mismatch"));
            return;
        }

        ResolvedUserProvider provider = tenantRegistry.resolvedProvider(pending.providerId(), pending.email());
        ProviderConfigDefinition config = externalProviderService.providerConfig(
                provider.realm(),
                provider.providerKey(),
                provider.providerType());
        validateProviderConfig(config);

        Map<String, Object> tokenResponse = exchangeAuthorizationCode(config, code);
        String externalAccessToken = String.valueOf(tokenResponse.get("access_token"));
        if (externalAccessToken == null || externalAccessToken.isBlank() || "null".equals(externalAccessToken)) {
            redirect(response, failureUrl("google_access_token_missing"));
            return;
        }

        Map<String, Object> userInfo = fetchUserInfo(config, externalAccessToken);
        String googleEmail = userInfo.get("email") == null ? null : String.valueOf(userInfo.get("email"));
        if (googleEmail == null || !provider.email().equalsIgnoreCase(googleEmail)) {
            redirect(response, failureUrl("google_email_mismatch"));
            return;
        }

        List<String> scopes = tenantRegistry.defaultBrowserScopes();
        ClientDefinition client = tenantRegistry.client(provider.realm(), "browser-login");
        String accessToken = tokenService.issueUserToken(
                provider.realm(),
                client.clientId(),
                provider.username(),
                scopes,
                provider.acls(),
                Map.of(
                        "auth_provider", provider.providerKey(),
                        "auth_provider_type", provider.providerType().name(),
                        "email", provider.email(),
                        "identity_provider", "google"));

        request.getSession(false).removeAttribute(PENDING_EXTERNAL_LOGIN);
        redirect(response, successUrl(accessToken));
    }

    @GetMapping("/service/me")
    Map<String, Object> currentUser(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String tokenValue = bearerToken(authorization);
        JWTClaimsSet claims = tokenService.verifiedClaims(tokenValue);
        String tenant = stringClaim(claims, "tenant");
        String username = stringClaim(claims, "user_id");
        UserDefinition user = tenantRegistry.user(tenant, username);

        List<String> scopes = stringListClaim(claims, "scp");
        List<String> roles = stringListClaim(claims, "roles");
        List<String> acls = stringListClaim(claims, "acls");
        List<String> audiences = claims.getAudience();

        return new LinkedHashMap<>(Map.of(
                "generatedAt", Instant.now().toString(),
                "tenant", Map.of(
                        "realm", tenant,
                        "issuer", claims.getIssuer()),
                "user", Map.of(
                        "id", user.id(),
                        "username", user.username(),
                        "email", user.email()),
                "authentication", Map.of(
                        "providerKey", stringClaim(claims, "auth_provider"),
                        "providerType", stringClaim(claims, "auth_provider_type"),
                        "clientId", stringClaim(claims, "azp")),
                "access", Map.of(
                        "scopes", scopes == null ? List.of() : scopes,
                        "roles", roles == null ? List.of() : roles,
                        "acls", acls == null ? List.of() : acls,
                        "audiences", audiences == null ? List.of() : audiences,
                        "services", properties.getDemo().getServices().stream()
                                .map(service -> withServiceAccess(service, scopes == null ? List.of() : scopes))
                                .toList()),
                "tokenClaims", claims.toJSONObject()));
    }

    @GetMapping("/login/demo-users")
    List<Map<String, String>> demoUsers() {
        return properties.getDemo().getCredentials();
    }

    private String normalizedEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "email is required");
        }
        return email.trim().toLowerCase();
    }

    private String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bearer token is required");
        }
        return authorization.substring("Bearer ".length());
    }

    private String stringClaim(JWTClaimsSet claims, String key) {
        try {
            String value = claims.getStringClaim(key);
            return value == null ? "" : value;
        } catch (ParseException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token claim " + key);
        }
    }

    private List<String> stringListClaim(JWTClaimsSet claims, String key) {
        try {
            List<String> value = claims.getStringListClaim(key);
            return value == null ? List.of() : value;
        } catch (ParseException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token claim " + key);
        }
    }

    private Map<String, String> credentialHints(String email) {
        return properties.getDemo().getCredentials().stream()
                .filter(entry -> entry.get("email").equalsIgnoreCase(email))
                .findFirst()
                .orElse(Map.of(
                        "email", email,
                        "password", "Use the seeded password for this account",
                        "otp", "Use the seeded OTP for this account",
                        "google", "requires a real Google account that matches the user's email"));
    }

    private Map<String, Object> toProviderPayload(AuthProviderDefinition provider) {
        return new LinkedHashMap<>(Map.of(
                "id", provider.id(),
                "providerKey", provider.providerKey(),
                "providerLabel", provider.providerLabel(),
                "providerType", provider.providerType().name(),
                "realm", provider.realm(),
                "realmDisplayName", provider.realmDisplayName(),
                "username", provider.username(),
                "email", provider.email()));
    }

    private Map<String, Object> toResolvedProviderPayload(ResolvedUserProvider provider) {
        return new LinkedHashMap<>(Map.of(
                "id", provider.id(),
                "providerKey", provider.providerKey(),
                "providerLabel", provider.providerLabel(),
                "providerType", provider.providerType().name(),
                "realm", provider.realm(),
                "realmDisplayName", provider.realmDisplayName(),
                "username", provider.username(),
                "email", provider.email()));
    }

    private Map<String, Object> withServiceAccess(ServiceDefinition service, List<String> scopes) {
        return new LinkedHashMap<>(Map.of(
                "service", service.getService(),
                "scope", service.getScope(),
                "audience", service.getAudience(),
                "granted", scopes.contains(service.getScope())));
    }

    private String buildAuthorizationUrl(ProviderConfigDefinition config, String state) {
        return UriComponentsBuilder.fromUriString(config.authorizationUri())
                .queryParam("client_id", config.clientId())
                .queryParam("redirect_uri", callbackUri())
                .queryParam("response_type", "code")
                .queryParam("scope", String.join(" ", config.scopes()))
                .queryParam("state", state)
                .queryParam("access_type", "online")
                .encode()
                .build()
                .toUriString();
    }

    private Map<String, Object> exchangeAuthorizationCode(ProviderConfigDefinition config, String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", config.clientId());
        form.add("client_secret", config.clientSecret());
        form.add("redirect_uri", callbackUri());
        form.add("grant_type", "authorization_code");
        return restClient.post()
                .uri(config.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
    }

    private Map<String, Object> fetchUserInfo(ProviderConfigDefinition config, String externalAccessToken) {
        return restClient.get()
                .uri(config.userInfoUri())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + externalAccessToken)
                .retrieve()
                .body(Map.class);
    }

    private PendingExternalLogin pendingLogin(HttpServletRequest request) {
        jakarta.servlet.http.HttpSession session = request.getSession(false);
        if (session == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing external login session");
        }
        PendingExternalLogin pending = (PendingExternalLogin) session.getAttribute(PENDING_EXTERNAL_LOGIN);
        if (pending == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing external login context");
        }
        return pending;
    }

    private void validateProviderConfig(ProviderConfigDefinition config) {
        if (config.clientId() == null || config.clientId().isBlank() || config.clientId().startsWith("SET_")
                || config.clientSecret() == null || config.clientSecret().isBlank() || config.clientSecret().startsWith("SET_")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Provider config is incomplete in DB for " + config.realm() + "/" + config.providerKey());
        }
    }

    private String callbackUri() {
        return authServerBaseUri + "/api/login/google/callback";
    }

    private String successUrl(String accessToken) {
        return successUri + "#access_token=" + urlEncode(accessToken);
    }

    private String failureUrl(String error) {
        return successUri + "#error=" + urlEncode(error);
    }

    private void redirect(HttpServletResponse response, String location) throws java.io.IOException {
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader(HttpHeaders.LOCATION, location);
    }

    private String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, Object>> handle(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of("error", ex.getReason()));
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    ResponseEntity<Map<String, Object>> handle(MissingRequestHeaderException ex) {
        if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(ex.getHeaderName())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Bearer token is required"));
        }
        return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
    }

    private record IdentifyRequest(String email) {
    }

    private record AuthenticateRequest(String email, Long providerId, String credential) {
    }

    private record GoogleStartRequest(String email, Long providerId) {
    }

    private record PendingExternalLogin(String email, long providerId, String realm, String providerKey, String state) {
    }
}
