package org.chenile.security.auth.integration.steps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.chenile.security.auth.integration.support.TestContext;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class IntegrationSteps {

    private final TestContext context;

    public IntegrationSteps(TestContext context) {
        this.context = context;
    }

    @Before
    public void setUp() {
        context.ensureEnvironmentStarted();
    }

    @Given("I request the OpenID configuration")
    public void iRequestTheOpenIdConfiguration() throws Exception {
        context.requestOpenIdConfiguration();
    }

    @When("I register a tenant client {string} with secret {string} for tenant {string} and scope {string}")
    public void iRegisterATenantClientWithSecretForTenantAndScope(
            String clientId,
            String clientSecret,
            String tenantId,
            String scope) throws Exception {
        context.registerClient(clientId, clientSecret, tenantId, scope);
    }

    @When("I request a client credentials token for {string} using secret {string} and scope {string}")
    public void iRequestAClientCredentialsTokenForUsingSecretAndScope(String clientId, String clientSecret, String scope)
            throws Exception {
        context.requestClientCredentialsToken(clientId, clientSecret, scope);
    }

    @When("I request a password token for user {string} using password {string} with client {string} and secret {string} and scope {string}")
    public void iRequestAPasswordTokenForUserUsingPasswordWithClientAndSecretAndScope(
            String username,
            String password,
            String clientId,
            String clientSecret,
            String scope) throws Exception {
        context.requestPasswordToken(username, password, clientId, clientSecret, scope);
    }

    @When("I call the public gateway path {string}")
    public void iCallThePublicGatewayPath(String path) throws Exception {
        context.callPublicGateway(path);
    }

    @When("I post the auth-server path {string} with JSON body:")
    public void iPostTheAuthServerPathWithJsonBody(String path, String body) throws Exception {
        context.postAuthServerJson(path, body);
    }

    @Then("the response status should be {int}")
    public void theResponseStatusShouldBe(Integer statusCode) {
        assertEquals(statusCode.intValue(), context.lastStatusCode(), context.lastBody());
    }

    @Then("the JSON field {string} should equal {string}")
    public void theJsonFieldShouldEqual(String field, String expectedValue) {
        assertEquals(expectedValue, String.valueOf(context.jsonField(field)));
    }

    @Then("the JSON field {string} should be present")
    public void theJsonFieldShouldBePresent(String field) {
        assertNotNull(context.jsonField(field), "Expected field " + field + " in " + context.lastBody());
    }

    @Then("the response body should contain {string}")
    public void theResponseBodyShouldContain(String expectedValue) {
        assertTrue(context.lastBody().contains(expectedValue), context.lastBody());
    }
}
