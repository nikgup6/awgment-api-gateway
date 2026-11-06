package com.techsophy.tsf.services.gateway.repo;

import com.techsophy.tsf.services.gateway.repository.OidcClientRegistrations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static com.techsophy.tsf.services.gateway.support.MockKeycloakServer.*;

class OidcClientRegistrationsTest
{
    @Test
    void keycloak26DiscoveryBuildsRegistration()
    {
        String issuer = issuerPrefix() + "medunited";
        ClientRegistration registration = OidcClientRegistrations.fromOidcIssuerLocation(issuer)
                .registrationId("medunited").clientId("awgment-api").clientSecret("test-secret").build();
        ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
        Assertions.assertEquals(issuer + "/protocol/openid-connect/auth", provider.getAuthorizationUri());
        Assertions.assertEquals(issuer + "/protocol/openid-connect/token", provider.getTokenUri());
        Assertions.assertEquals(issuer + "/protocol/openid-connect/certs", provider.getJwkSetUri());
        Assertions.assertEquals(issuer + "/protocol/openid-connect/userinfo", provider.getUserInfoEndpoint().getUri());
        Assertions.assertEquals(issuer, provider.getConfigurationMetadata().get("issuer"));
        Assertions.assertTrue(provider.getConfigurationMetadata().containsKey("mtls_endpoint_aliases"));
        Assertions.assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registration.getClientAuthenticationMethod());
        Assertions.assertTrue(registration.getScopes().contains("openid"));
    }

    @Test
    void matchesSpringSecurityForDiscoveryWithoutNestedObjects()
    {
        String issuer = issuerPrefix() + LEGACY_REALM;
        ClientRegistration ours = OidcClientRegistrations.fromOidcIssuerLocation(issuer).clientId("awgment-api").build();
        ClientRegistration spring = ClientRegistrations.fromOidcIssuerLocation(issuer).clientId("awgment-api").build();
        Assertions.assertEquals(spring.getRegistrationId(), ours.getRegistrationId());
        Assertions.assertEquals(spring.getClientName(), ours.getClientName());
        // Spring Security 6 no longer copies scopes_supported into the registration; ours keeps the previous behaviour
        Assertions.assertTrue(ours.getScopes().contains("openid"));
        Assertions.assertEquals(spring.getClientAuthenticationMethod(), ours.getClientAuthenticationMethod());
        Assertions.assertEquals(spring.getAuthorizationGrantType(), ours.getAuthorizationGrantType());
        Assertions.assertEquals(spring.getRedirectUri(), ours.getRedirectUri());
        Assertions.assertEquals(spring.getProviderDetails().getAuthorizationUri(), ours.getProviderDetails().getAuthorizationUri());
        Assertions.assertEquals(spring.getProviderDetails().getTokenUri(), ours.getProviderDetails().getTokenUri());
        Assertions.assertEquals(spring.getProviderDetails().getJwkSetUri(), ours.getProviderDetails().getJwkSetUri());
        Assertions.assertEquals(spring.getProviderDetails().getUserInfoEndpoint().getUri(), ours.getProviderDetails().getUserInfoEndpoint().getUri());
        Assertions.assertEquals(spring.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(),
                ours.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
    }

    @Test
    void springSecurityNowAcceptsKeycloak26Discovery()
    {
        // Spring Security 6.5 parses Keycloak 26 discovery itself; OidcClientRegistrations is kept so that
        // registrations stay identical to the pre-upgrade behaviour (e.g. scopes from scopes_supported).
        String issuer = issuerPrefix() + "medunited";
        Assertions.assertDoesNotThrow(() -> ClientRegistrations.fromOidcIssuerLocation(issuer));
    }

    @Test
    void issuerMismatchIsRejected()
    {
        String issuer = issuerPrefix() + MISMATCH_REALM;
        Assertions.assertThrows(IllegalStateException.class, () -> OidcClientRegistrations.fromOidcIssuerLocation(issuer));
    }

    @Test
    void missingRealmIsRejected()
    {
        String issuer = issuerPrefix() + MISSING_REALM;
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> OidcClientRegistrations.fromOidcIssuerLocation(issuer));
        Assertions.assertTrue(e.getMessage().contains(issuer));
    }
}
