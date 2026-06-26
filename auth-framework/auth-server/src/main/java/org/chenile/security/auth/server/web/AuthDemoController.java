package org.chenile.security.auth.server.web;

import org.chenile.security.auth.server.config.AuthServerProperties;
import org.chenile.security.auth.server.config.AuthServerProperties.Scenario;
import org.chenile.security.auth.server.config.AuthServerProperties.ServiceDefinition;
import org.chenile.security.auth.server.service.TokenService;
import org.chenile.security.auth.framework.contract.TenantRegistry;
import org.chenile.security.auth.framework.contract.TenantRegistry.AuthProviderDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry.ClientDefinition;
import org.chenile.security.auth.framework.contract.TenantRegistry.ResolvedUserProvider;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/demo")
public class AuthDemoController {

    private final TenantRegistry tenantRegistry;
    private final TokenService tokenService;
    private final AuthServerProperties properties;

    public AuthDemoController(
            TenantRegistry tenantRegistry,
            TokenService tokenService,
            AuthServerProperties properties) {
        this.tenantRegistry = tenantRegistry;
        this.tokenService = tokenService;
        this.properties = properties;
    }

    @GetMapping("/scenarios")
    List<Map<String, Object>> scenarios() {
        return properties.getDemo().getScenarios().stream()
                .map(this::toScenarioPayload)
                .toList();
    }

    @GetMapping("/context")
    Map<String, Object> demoContext(
            @RequestParam(required = false) String scenario,
            @RequestParam(required = false) Long providerId) {
        String selectedScenarioKey = scenario == null || scenario.isBlank()
                ? properties.getDemo().getScenarios().stream()
                        .findFirst()
                        .map(Scenario::getKey)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No demo scenarios configured"))
                : scenario;
        Scenario selectedScenario = properties.getDemo().getScenarios().stream()
                .filter(candidate -> candidate.getKey().equals(selectedScenarioKey))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Unknown demo scenario " + selectedScenarioKey));

        List<AuthProviderDefinition> providers = tenantRegistry.providersForEmail(selectedScenario.getEmail());
        if (providers.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "No providers configured for " + selectedScenario.getEmail());
        }

        long resolvedProviderId = providerId != null
                ? providerId
                : providers.getFirst().id();
        boolean providerExists = providers.stream().anyMatch(candidate -> candidate.id() == resolvedProviderId);
        if (!providerExists) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Provider " + resolvedProviderId + " is not available for " + selectedScenario.getEmail());
        }
        ResolvedUserProvider provider = tenantRegistry.resolvedProvider(resolvedProviderId, selectedScenario.getEmail());
        List<String> scopes = tenantRegistry.defaultBrowserScopes();
        ClientDefinition client = tenantRegistry.client(provider.realm(), selectedScenario.getClientId());
        String accessToken = tokenService.issueUserToken(
                provider.realm(),
                selectedScenario.getClientId(),
                provider.username(),
                scopes,
                provider.acls());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", Instant.now().toString());
        payload.put("scenario", Map.of(
                "key", selectedScenario.getKey(),
                "label", selectedScenario.getLabel()));
        payload.put("availableScenarios", properties.getDemo().getScenarios().stream().map(this::toScenarioPayload).toList());
        payload.put("providerOptions", providers.stream().map(this::toProviderPayload).toList());
        payload.put("selectedProviderId", provider.id());
        payload.put("tenant", Map.of(
                "realm", provider.realm(),
                "displayName", provider.realmDisplayName(),
                "issuer", tokenService.issuer(provider.realm())));
        payload.put("user", Map.of(
                "id", provider.userId(),
                "username", provider.username(),
                "email", provider.email(),
                "userIdClaim", provider.username()));
        payload.put("authentication", Map.of(
                "clientId", selectedScenario.getClientId(),
                "provider", toProviderPayload(provider),
                "scopes", scopes,
                "roles", provider.acls(),
                "acls", provider.acls()));
        payload.put("client", Map.of(
                "clientId", client.clientId(),
                "clientCredentialsEnabled", client.clientCredentialsEnabled(),
                "passwordGrantEnabled", client.passwordGrantEnabled(),
                "allowedScopes", client.allowedScopes()));
        payload.put("services", properties.getDemo().getServices().stream()
                .map(service -> withServiceAccess(service, scopes))
                .toList());
        payload.put("token", Map.of(
                "value", accessToken,
                "claims", decodeClaims(accessToken)));
        return payload;
    }

    private Map<String, Object> toScenarioPayload(Scenario scenario) {
        List<AuthProviderDefinition> providers = tenantRegistry.providersForEmail(scenario.getEmail());
        return new LinkedHashMap<>(Map.of(
                "key", scenario.getKey(),
                "label", scenario.getLabel(),
                "email", scenario.getEmail(),
                "clientId", scenario.getClientId(),
                "providerCount", providers.size(),
                "providers", providers.stream().map(this::toProviderPayload).toList()));
    }

    private Map<String, Object> toProviderPayload(AuthProviderDefinition provider) {
        return new LinkedHashMap<>(Map.of(
                "id", provider.id(),
                "providerKey", provider.providerKey(),
                "providerLabel", provider.providerLabel(),
                "providerType", provider.providerType().name(),
                "realm", provider.realm(),
                "username", provider.username(),
                "email", provider.email()));
    }

    private Map<String, Object> toProviderPayload(ResolvedUserProvider provider) {
        return new LinkedHashMap<>(Map.of(
                "id", provider.id(),
                "providerKey", provider.providerKey(),
                "providerLabel", provider.providerLabel(),
                "providerType", provider.providerType().name(),
                "realm", provider.realm(),
                "username", provider.username(),
                "email", provider.email()));
    }

    private Map<String, Object> decodeClaims(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().toJSONObject();
        } catch (ParseException ex) {
            throw new IllegalStateException("Failed to decode demo token", ex);
        }
    }

    private Map<String, Object> withServiceAccess(ServiceDefinition service, List<String> scopes) {
        return new LinkedHashMap<>(Map.of(
                "service", service.getService(),
                "scope", service.getScope(),
                "audience", service.getAudience(),
                "granted", scopes.contains(service.getScope())));
    }
}
