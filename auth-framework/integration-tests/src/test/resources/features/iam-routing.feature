Feature: Configurable IAM integration

  Scenario: OpenID metadata is exposed by the configured auth provider
    Given I request the OpenID configuration
    Then the response status should be 200
    And the JSON field "issuer" should equal "http://localhost:9000/realms/tenant-alpha"
    And the JSON field "token_endpoint" should be present

  Scenario: Email-first login discovery returns available providers for configured user
    When I post the auth-server path "/api/login/identify" with JSON body:
      """
      {"email":"gaurav.bhardwaj@getvymo.com"}
      """
    Then the response status should be 200
    And the JSON field "nextStep" should equal "select-provider"
    And the response body should contain "GOOGLE"
    And the response body should contain "tenant-alpha"

  Scenario: Client credentials token can reach both protected services through the gateway
    When I request a client credentials token for "system-client" using secret "system-client-secret" and scope "gateway.access service-a.read service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/summary"
    Then the response status should be 200
    And the JSON field "service" should equal "service-a"
    When I call the public gateway path "/api/b/customers/portfolio"
    Then the response status should be 200
    And the JSON field "service" should equal "service-b"

  Scenario: Token without service-a scope is rejected by service-a through the gateway
    When I request a client credentials token for "system-client" using secret "system-client-secret" and scope "gateway.access"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/summary"
    Then the response status should be 401

  Scenario: Token without service-b scope is rejected by service-b through the gateway
    When I request a password token for user "alice" using password "Alpha#Pass1" with client "user-test-client" and secret "user-test-secret" and scope "gateway.access service-a.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/b/customers/portfolio"
    Then the response status should be 401

  Scenario: Issued token is validated end to end and context is propagated from service-a to service-b
    When I request a client credentials token for "system-client" using secret "system-client-secret" and scope "gateway.access service-a.read service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/secure-bridge"
    Then the response status should be 200
    And the JSON field "service" should equal "service-a"
    And the JSON field "requestContext.userId" should equal "system-client"
    And the JSON field "requestContext.tenantId" should equal "platform"
    And the JSON field "requestContext.headerUserId" should equal "system-client"
    And the JSON field "requestContext.headerTenantId" should equal "platform"
    And the JSON field "downstreamContext.service" should equal "service-b"
    And the JSON field "downstreamContext.requestContext.userId" should equal "system-client"
    And the JSON field "downstreamContext.requestContext.tenantId" should equal "platform"
    And the JSON field "downstreamContext.requestContext.headerUserId" should equal "system-client"
    And the JSON field "downstreamContext.requestContext.headerTenantId" should equal "platform"
    And the response body should contain "SCOPE_gateway.access"
    And the response body should contain "SCOPE_service-a.read"
    And the response body should contain "SCOPE_service-b.read"

  Scenario: Newly registered tenant-gamma client can call service-a with isolated tenant claim
    When I register a tenant client "tenant-gamma-client" with secret "tenant-gamma-secret" for tenant "tenant-gamma" and scope "gateway.access service-a.read"
    Then the response status should be 201
    When I request a client credentials token for "tenant-gamma-client" using secret "tenant-gamma-secret" and scope "gateway.access service-a.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/summary"
    Then the response status should be 200
    And the JSON field "service" should equal "service-a"
    And the JSON field "tenantId" should equal "tenant-gamma"
    And the JSON field "userId" should equal "tenant-gamma-client"
    And the response body should contain "A-TENANT_GAMMA-3001"

  Scenario: Newly registered tenant-delta client can call service-b with isolated tenant claim
    When I register a tenant client "tenant-delta-client" with secret "tenant-delta-secret" for tenant "tenant-delta" and scope "gateway.access service-b.read"
    Then the response status should be 201
    When I request a client credentials token for "tenant-delta-client" using secret "tenant-delta-secret" and scope "gateway.access service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/b/customers/portfolio"
    Then the response status should be 200
    And the JSON field "service" should equal "service-b"
    And the JSON field "tenantId" should equal "tenant-delta"
    And the JSON field "userId" should equal "tenant-delta-client"
    And the response body should contain "B-TENANT_DELTA-990"

  Scenario: Alice token carries tenant-alpha ACLs across gateway, service-a, and service-b
    When I request a password token for user "alice" using password "Alpha#Pass1" with client "user-test-client" and secret "user-test-secret" and scope "gateway.access service-a.read service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/secure-bridge"
    Then the response status should be 200
    And the JSON field "requestContext.userId" should equal "alice"
    And the JSON field "requestContext.tenantId" should equal "tenant-alpha"
    And the JSON field "downstreamContext.requestContext.userId" should equal "alice"
    And the JSON field "downstreamContext.requestContext.tenantId" should equal "tenant-alpha"
    And the response body should contain "A-ALPHA-1001"
    And the response body should contain "B-ALPHA-900"
    And the response body should contain "bridge:invoke"
    And the response body should contain "orders:read"

  Scenario: Bob token carries tenant-beta ACLs across gateway, service-a, and service-b
    When I request a password token for user "bob" using password "Bravo#Pass2" with client "user-test-client" and secret "user-test-secret" and scope "gateway.access service-a.read service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/secure-bridge"
    Then the response status should be 200
    And the JSON field "requestContext.userId" should equal "bob"
    And the JSON field "requestContext.tenantId" should equal "tenant-beta"
    And the JSON field "downstreamContext.requestContext.userId" should equal "bob"
    And the JSON field "downstreamContext.requestContext.tenantId" should equal "tenant-beta"
    And the response body should contain "A-BETA-2001"
    And the response body should contain "B-BETA-950"
    And the response body should contain "customers:read"
    And the response body should contain "portfolio:view"

  Scenario: Ops admin token carries platform ACLs across gateway, service-a, and service-b
    When I request a password token for user "ops-admin" using password "Admin#Pass3" with client "user-test-client" and secret "user-test-secret" and scope "gateway.access service-a.read service-b.read"
    Then the response status should be 200
    And the JSON field "access_token" should be present
    When I call the public gateway path "/api/a/orders/secure-bridge"
    Then the response status should be 200
    And the JSON field "requestContext.userId" should equal "ops-admin"
    And the JSON field "requestContext.tenantId" should equal "platform"
    And the JSON field "downstreamContext.requestContext.userId" should equal "ops-admin"
    And the JSON field "downstreamContext.requestContext.tenantId" should equal "platform"
    And the response body should contain "A-ALPHA-1001"
    And the response body should contain "A-BETA-2001"
    And the response body should contain "B-ALPHA-900"
    And the response body should contain "B-BETA-950"
    And the response body should contain "admin:all"
    And the response body should contain "customers:read"
    And the response body should contain "orders:read"
