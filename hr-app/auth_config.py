from keycloak import KeycloakOpenID

keycloak_openid = KeycloakOpenID(
    server_url="http://localhost:8080/hr-app",
    client_id="hr-app",
    realm_name="enterprise-zero-trust",
    client_secret_key="zDWTlPhVke4jbLWa7rXxoXIJm4NwAEWF",
)