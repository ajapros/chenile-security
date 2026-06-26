package org.chenile.security.auth.integration.support;

import java.nio.file.Path;
import java.time.Duration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

public final class IntegrationEnvironment {

    private static final Network NETWORK = Network.newNetwork();
    private static final Path SECURITY_ROOT = Path.of(System.getProperty("user.dir")).getParent().getParent();
    private static final Path WORKSPACE_ROOT = SECURITY_ROOT.getParent();
    private static final String FRAMEWORK_VERSION = System.getProperty("project.version", "2.1.24");
    private static final String SAMPLE_VERSION = "0.0.1-SNAPSHOT";
    private static final DockerImageName JAVA_25 = DockerImageName.parse("eclipse-temurin:25-jre");
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("auth_server")
            .withUsername("auth_user")
            .withPassword("auth_pass")
            .withNetwork(NETWORK)
            .withNetworkAliases("postgres");
    private static final GenericContainer<?> AUTH_SERVER = createService(
            WORKSPACE_ROOT.resolve("chenile-samples/security-auth-sample/auth-server-app"),
            "security-auth-sample-server",
            SAMPLE_VERSION,
            9000,
            "auth-server",
            container -> container
                    .withEnv("SERVER_PORT", "9000")
                    .withEnv("CHENILE_SECURITY_ISSUER_BASE", "http://localhost:9000")
                    .withEnv("SPRING_DATASOURCE_URL", "jdbc:postgresql://postgres:5432/auth_server")
                    .withEnv("SPRING_DATASOURCE_USERNAME", "auth_user")
                    .withEnv("SPRING_DATASOURCE_PASSWORD", "auth_pass")
                    .dependsOn(POSTGRES));
    private static final String AUTH_SERVER_INTERNAL_URI = "http://auth-server:9000";

    private static final GenericContainer<?> SERVICE_A = createService(
            WORKSPACE_ROOT.resolve("chenile-samples/security-auth-sample/service-a"),
            "security-auth-sample-service-a",
            SAMPLE_VERSION,
            8081,
            "service-a",
            container -> container
                    .withEnv("CHENILE_SECURITY_JWT_ISSUER_BASE", "http://localhost:9000")
                    .withEnv("CHENILE_SECURITY_JWT_JWK_BASE_URI", AUTH_SERVER_INTERNAL_URI)
                    .withEnv("SAMPLE_SECURITY_SERVICE_B_URI", "http://service-b:8082")
                    .dependsOn(AUTH_SERVER));

    private static final GenericContainer<?> SERVICE_B = createService(
            WORKSPACE_ROOT.resolve("chenile-samples/security-auth-sample/service-b"),
            "security-auth-sample-service-b",
            SAMPLE_VERSION,
            8082,
            "service-b",
            container -> container
                    .withEnv("CHENILE_SECURITY_JWT_ISSUER_BASE", "http://localhost:9000")
                    .withEnv("CHENILE_SECURITY_JWT_JWK_BASE_URI", AUTH_SERVER_INTERNAL_URI)
                    .dependsOn(AUTH_SERVER));

    private static final GenericContainer<?> GATEWAY = createService(
            SECURITY_ROOT.resolve("auth-framework/gateway"),
            "chenile-security-gateway",
            FRAMEWORK_VERSION,
            8080,
            "gateway",
            container -> container
                    .withEnv("SPRING_APPLICATION_JSON", gatewayConfiguration())
                    .dependsOn(AUTH_SERVER, SERVICE_A, SERVICE_B));

    static {
        POSTGRES.start();
        AUTH_SERVER.start();
        SERVICE_A.start();
        SERVICE_B.start();
        GATEWAY.start();
    }

    private IntegrationEnvironment() {
    }

    public static String authServerBaseUrl() {
        return "http://localhost:" + AUTH_SERVER.getMappedPort(9000);
    }

    public static String gatewayBaseUrl() {
        return "http://localhost:" + GATEWAY.getMappedPort(8080);
    }

    private static GenericContainer<?> createService(
            Path modulePath,
            String artifactId,
            String version,
            int exposedPort,
            String networkAlias,
            ContainerCustomizer customizer) {
        Path jarPath = modulePath.resolve("target/" + artifactId + "-" + version + ".jar");

        GenericContainer<?> container = new GenericContainer<>(JAVA_25)
                .withNetwork(NETWORK)
                .withNetworkAliases(networkAlias)
                .withExposedPorts(exposedPort)
                .withCopyFileToContainer(MountableFile.forHostPath(jarPath), "/app/app.jar")
                .withCommand("java", "-jar", "/app/app.jar")
                .waitingFor(Wait.forHttp("/actuator/health")
                        .forPort(exposedPort)
                        .forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(4)));

        customizer.customize(container);
        return container;
    }

    private static String gatewayConfiguration() {
        return """
                {
                  "chenile": {
                    "security": {
                      "gateway": {
                        "auth-server": {
                          "uri": "%s"
                        },
                        "security": {
                          "issuer-base": "http://localhost:9000",
                          "jwk-base-uri": "%s"
                        },
                        "relay": {
                          "forward-authorization": true,
                          "headers": [
                            {"name": "x-tenant-id", "claim": "tenant"},
                            {"name": "x-user-id", "claim": "user_id"},
                            {"name": "x-acls", "claim": "acls"},
                            {"name": "x-chenile-tenant-id", "claim": "tenant"},
                            {"name": "x-chenile-auth-user", "claim": "user_id"},
                            {"name": "x-chenile-deviceid", "claim": "device_id"},
                            {"name": "x-vymo-user-details", "claim": "user_details", "format": "json"},
                            {"name": "x-vymo-locale", "claim": "locale"},
                            {"name": "vymo-locale", "claim": "vymo_locale"}
                          ]
                        },
                        "routes": [
                          {
                            "id": "service-a",
                            "paths": ["/api/a/**"],
                            "uri": "http://service-a:8081",
                            "rewrite-regex": "/api/a/(?<segment>.*)",
                            "rewrite-replacement": "/api/a/${segment}"
                          },
                          {
                            "id": "service-b",
                            "paths": ["/api/b/**"],
                            "uri": "http://service-b:8082",
                            "rewrite-regex": "/api/b/(?<segment>.*)",
                            "rewrite-replacement": "/api/b/${segment}"
                          }
                        ]
                      }
                    }
                  }
                }
                """.formatted(AUTH_SERVER_INTERNAL_URI, AUTH_SERVER_INTERNAL_URI);
    }

    @FunctionalInterface
    private interface ContainerCustomizer {
        void customize(GenericContainer<?> container);
    }
}
