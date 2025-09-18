RFC standard: https://datatracker.ietf.org/doc/html/rfc7591
docker oauth2.0 flow: https://docs.docker.com/extensions/extensions-sdk/guides/oauth2-flow/
MCO auth: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
401 failover: https://stytch.com/blog/oauth-for-mcp-explained-with-a-real-world-example/
Agentic oauth: https://stytch.com/blog/agent-to-agent-oauth-guide/




🎯 Key Implications for Your Implementation:

  Current OAuth2-proxy vs RFC 7591 DCR:

  Your current approach:
  - Static client registration (manual setup)
  - OAuth2-proxy container with pre-configured client credentials
  - Works but requires manual configuration per MCP server

  RFC 7591 DCR approach:
  - Dynamic client registration - clients register themselves automatically
  - Discovery-based - find registration endpoints automatically
  - Programmatic - no manual OAuth app creation needed

  🔄 Enhanced Flow with DCR:

  graph TD
      A[401 Error] --> B[Discover .well-known/oauth-authorization-server]
      B --> C[POST /register with client metadata]
      C --> D[Receive client_id/client_secret]
      D --> E[Open browser for user consent]
      E --> F[Handle callback with auth code]
      F --> G[Exchange code for access token]
      G --> H[Retry original MCP request with token]

  🐳 Docker Compose Benefits:

  Your Dex setup would provide:
  - Containerized OAuth server (Dex)
  - Dynamic client registration endpoint
  - Automatic redirect URI handling
  - Network isolation with proper container communication
  - Development/production environment handling

  💡 Implementation Strategy:

  1. Phase 1: Implement "direct-first, 401-fallback" with existing OAuth2-proxy
  2. Phase 2: Add RFC 7591 DCR discovery and registration
  3. Phase 3: Docker Compose setup with Dex for full automation

  This would make your MCP scanner industry-leading - most tools don't handle dynamic client registration properly. The automatic discovery and registration would
  provide seamless OAuth for any RFC 7591 compliant MCP server.

  This is a significant architectural enhancement that would set your scanner apart! 🚀

  Todos
  ☐ Research and implement OAuth 2.0 Dynamic Client Registration (RFC 7591) for MCP
  ☐ Implement try-direct-first with 401 OAuth fallback
  ☐ Set up Docker Compose with Dex for dynamic client registration





  OAuth 2.0 Dynamic Client Registration (DCR) allows client applications to register themselves programmatically with an OAuth 2.0 Authorization Server, rather than requiring manual pre-registration. This is particularly useful in large-scale ecosystems or when dealing with numerous third-party applications.
Key aspects of DCR:
Automated Client Onboarding: DCR enables applications to register themselves by sending a POST request with client metadata (like redirect URIs, grant types, and scopes) to a designated registration endpoint on the Authorization Server. This eliminates the need for manual configuration and speeds up integration.
RFC 7591 Compliance: The OAuth 2.0 Dynamic Client Registration Protocol is defined in RFC 7591. Implementations should adhere to this specification for interoperability.
Security Considerations: The registration endpoint is typically protected to prevent unauthorized client registrations. Common methods include:
Access Token Protection: Requiring an access token with a specific scope (e.g., dcr_register) issued to a separate, pre-registered service client.
Software Statements: Requiring a signed JWT (JSON Web Token) containing client metadata, verified using public keys configured on the Authorization Server.
Signed Request Body: Requiring the entire registration request body to be signed, also verified using public keys.
Client Metadata: The registration request includes various client metadata, such as:
redirect_uris: URIs where the Authorization Server will redirect the user after authorization.
grant_types: Supported OAuth 2.0 grant types (e.g., authorization_code, client_credentials).
response_types: Supported OAuth 2.0 response types (e.g., code, token).
client_name: A human-readable name for the client.
client_uri: A URI for the client's homepage.
logo_uri: A URI for the client's logo.
Web Consent and DCR:
Web consent, in the context of OAuth 2.0, refers to the user's interaction with the Authorization Server to grant or deny access to their resources by a client application. DCR facilitates the registration of these client applications, which then participate in the authorization flow where web consent is obtained.
User Experience: When a dynamically registered client requests access to a user's resources, the Authorization Server presents a consent screen to the user. This screen typically displays information about the client (e.g., its name, logo, and requested scopes) and asks the user to approve or deny the access request.
Scope Management: DCR allows clients to declare their intended scopes during registration. These scopes are then presented to the user on the consent screen, enabling informed consent.
Reduced Friction: By automating client registration, DCR streamlines the process of integrating new applications, which indirectly improves the overall user experience by making more services available with less administrative overhead.



When using Docker with OAuth 2.0 dynamic clients, a web consent redirect requires a dynamic client registration service (like Dex), and a Docker Compose setup that properly handles networking for the callback URLs. This approach automates the process of registering applications and obtaining user consent without manual configuration.
Key components for a Docker-based setup
Authorization server: An OAuth 2.0 or OpenID Connect (OIDC) compliant identity provider (IdP). A common choice for a Dockerized environment is Dex, an open-source IdP that runs in a container.
Dynamic Client Registration (DCR): A service that allows client applications to register themselves programmatically with the authorization server. DCR is defined in RFC 7591 and eliminates the need for manual setup of each client.
Web client application: The service that needs to access user data. It is deployed in its own Docker container and initiates the registration and authorization flows.
Redirect URI: The callback URL on the client application where the authorization server redirects the user after authentication and consent. In a dynamic setup, this URI is provided during the DCR process.
Step-by-step workflow
Client initiates registration: The web client sends a POST request to the authorization server's client registration endpoint. The request includes metadata like the redirect_uris.
Server registers client: The authorization server validates the request and creates a new client entry. It responds with a unique client_id and, for confidential clients, a client_secret.
User grants consent:
The web client redirects the user's browser to the authorization endpoint on the authorization server.
The server prompts the user to log in and grant consent for the requested permissions (scopes).
Authorization code is sent:
If the user grants consent, the server redirects the browser back to the web client's specified redirect_uri.
The redirect URL includes a temporary authorization_code.
Client exchanges code for tokens: The web client uses the authorization_code and its credentials (client_id, client_secret) to make a secure back-channel request to the server's token endpoint.
Access token is received: The authorization server validates the code and client details, then issues an access_token and, optionally, a refresh_token.
Example Docker Compose setup with Dex
A Docker Compose file orchestrates the authorization server (Dex) and the web client. The key is to ensure the containers can communicate and that the client's registered redirect URI is accessible.
docker-compose.yml
yaml
version: '3.7'
services:
  dex:
    image: ghcr.io/dexidp/dex:v2.37.0
    command: dex serve /etc/dex/config.yaml
    volumes:
      - ./dex/config.yaml:/etc/dex/config.yaml
    ports:
      - "5556:5556"
  web-client:
    build: ./web-client # Build a custom image for your web client
    depends_on:
      - dex
    ports:
      - "8080:8080"
Dex configuration (dex/config.yaml)
This configuration tells Dex where to listen and which connectors to use. Here, a mock static password connector is used for testing.
yaml
issuer: http://dex:5556
storage:
  type: memory
web:
  http: 0.0.0.0:5556
staticClients:
  # This section is for clients that aren't dynamically registered
  # but is useful for testing. Dynamic registration is the real goal.
  - id: example-app
    redirectURIs:
      - 'http://localhost:8080/callback'
    name: 'Example App'
    secret: some-secret
connectors:
  - type: staticpassword
    id: static
    name: Static Passwords
    config:
      users:
        - email: "admin@example.com"
          hash: "$2a$10$w82E/Yg10H4rNfM7Q32.Y.d2jKjY.07kRj.x1v.xLz.4z5z7Z89z.a" # password
          username: "admin"
Web client implementation
The web client would be a simple application (e.g., using Python Flask or Node.js Express) that performs the following:
Dynamic registration: On startup, or when a new client needs to be onboarded, make a POST request to http://dex:5556/register with its metadata, including redirect_uris.
Authorization flow: Implement a handler for the /login route that redirects the user to http://dex:5556/auth?client_id=...&redirect_uri=....
Callback handler: Implement a /callback route to handle the redirect from Dex. This handler receives the authorization_code and exchanges it for an access_token.
Handling dynamic redirect URIs in Docker
To handle different environments (e.g., development on localhost vs. production with a public URL), you must provide the correct redirect_uris during dynamic registration.
For development: Use localhost and the local port, making sure the client container's port is exposed via docker-compose.yml. For example: http://localhost:8080/callback.
For production: Use the public domain name and protocol.
For scalable deployments: Use environment variables in the client's Dockerfile or Docker Compose setup to provide the correct redirect URI at runtime.
# In docker-compose.yml for the web-client service
environment:
  - OAUTH_REDIRECT_URI=http://my-public





post reserach:

Perfect! These resources provide the exact specification for implementing MCP OAuth correctly. Here's what we learned:

  🎯 MCP OAuth 2.1 Specification Requirements:

  Critical MCP-Specific Requirements:

  1. Resource Parameter: Must include resource parameter identifying the MCP server
  2. Bearer Token: Use Authorization: Bearer <token> header (never query string)
  3. Dynamic Client Registration: Recommended via RFC 7591
  4. PKCE: Must implement Proof Key for Code Exchange
  5. OAuth 2.1 Draft: Follow updated OAuth spec (not 2.0)

  🔄 Complete MCP OAuth Flow:

  graph TD
      A[MCP Request] --> B[401 Unauthorized]
      B --> C[Discover .well-known/oauth-authorization-server]
      C --> D[POST /register - Dynamic Client Registration]
      D --> E[Open Browser with resource parameter]
      E --> F[User Consent & Auth Code]
      F --> G[Exchange code for Bearer token with PKCE]
      G --> H[Retry MCP request with Authorization: Bearer header]

  🐳 Docker Implementation Strategy:

  Phase 1 - Enhanced Fallback OAuth:
  - Implement "direct-first, 401-fallback" pattern
  - Add proper Bearer token support
  - Include resource parameter for MCP servers

  Phase 2 - Full MCP OAuth 2.1:
  - Add RFC 8414 discovery (.well-known/oauth-authorization-server)
  - Implement RFC 7591 dynamic client registration
  - Add PKCE support for security
  - Use Docker Desktop-style browser opening

  💡 Key Implementation Insights:

  1. Resource Parameter: resource=https://mcp.notion.com/mcp identifies the target MCP server
  2. Browser Flow: Use ddClient.host.openExternal() pattern adapted for your scanner
  3. Token Storage: Secure token handling in containerized environment
  4. PKCE: Code challenge/verifier for additional security

  This gives us a complete roadmap for implementing proper MCP OAuth 2.1 compliance! The combination of MCP spec + Docker OAuth patterns provides everything needed.


