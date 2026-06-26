# chenile-security
This repository contains Chenile security modules. It now keeps the existing security framework and the new auth/gateway framework in separate directories so applications can choose the security model they need.

## Directory layout

- `legacy-security/`: existing Chenile security modules, including Keycloak integration, security API, security interceptor, and Cucumber security utilities.
- `auth-framework/`: new Spring Security auth-server, resource-server, and gateway framework.

## Existing security framework

Use `legacy-security` modules when an application already uses the current Chenile security API, Keycloak integration, or `security-interceptor`.

Published artifact names remain stable:

- `chenile-security-api`
- `chenile-security`
- `security-interceptor`
- `cucumber-sec-utils`

Only the source directory changed.

## New auth/gateway framework

Use `auth-framework` modules when an application wants Chenile-managed auth-server, gateway routing, JWT validation, tenant-aware request context, and trusted claim-to-header relay.

New opt-in artifacts:

- `chenile-security-auth-core`
- `chenile-security-auth-server`
- `chenile-security-gateway`
- `chenile-security-starter-auth-server`
- `chenile-security-starter-gateway`
- `chenile-security-starter-resource-server`

The new modules use Spring Boot 4, Java 25, and Spring Cloud Gateway through the `2025.1.2` Spring Cloud BOM.

Applications that already have an identity provider can skip `chenile-security-auth-server` and use only the gateway/resource-server starter modules.

## Sample

See `chenile-samples/security-auth-sample` for a Postgres-backed reference implementation with an auth-server app, protected services, runtime assets, and React demo UI.

# About chenile

Chenile is an open source framework for creating Micro services using Java and Spring Boot. 
Please check the details out at https://chenile.org

It provides an interception framework to decouple functional and non-functional requirements.
Chenile avoids the need to write repetitive code. It encourages modular coding best practices. 

In addition to creating REST services, Chenile services can also be used to create event processors, 
schedulers (with quartz), a file watcher etc. without the need for rewriting the code. 

Chenile has a state machine and an orchestration engine.  

The orchestration engine is internally used by Chenile to provide an interception framework that helps in 
disinter-mediating traffic irrespective of the incoming protocol (HTTP, message etc.)

Hence Chenile also serves like an IN-VM message bus. Chenile also facilitates easy swagger documentation 
(using Spring doc). 
Chenile allows the development of Cucumber based BDD tests with most of the plumbing already in place.
Chenile also is integrated with [keycloak](https://www.keycloak.org/) for security. 

Finally, Chenile ships with its own code generators to ease the development of micro services. 
Please see [Code Generation Repository](https://github.com/rajakolluru/chenile-gen) for more information 
about the code generator.

