package com.techsophy.tsf.services.gateway.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.techsophy.tsf.services.gateway.support.MockKeycloakServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import java.time.Instant;
import java.util.Date;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.TEST_ACTIVE_PROFILE;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.X_TENANT;

/**
 * Real HTTP through the security chain and gateway filters. Only rejections are checked: they happen before
 * the request is routed, so no downstream service is needed.
 */
@ActiveProfiles(TEST_ACTIVE_PROFILE)
@AutoConfigureWebTestClient
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"CORS_ALLOWEDORIGINS=VALUE", "ADD_ALLOWEDMETHOD=VALUE2", "ADD_ALLOWEDHEADER=VALUE3"})
class PublicRouteRejectionHttpTest
{
    static final String PUBLIC_PATH = "/api/config-server/x";
    static final String PRIVATE_PATH = "/api/core/x";

    @Autowired
    WebTestClient client;

    @DynamicPropertySource
    static void keycloakProperties(DynamicPropertyRegistry registry)
    {
        registry.add("keycloak.issuer-uri", MockKeycloakServer::issuerPrefix);
    }

    @Test
    void bareJwtOnPublicRouteIsRejectedTest()
    {
        client.get().uri(PUBLIC_PATH).header(HttpHeaders.AUTHORIZATION, bareJwt()).exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, value -> value.contains("invalid_token"));
    }

    @Test
    void bareJwtOnPrivateRouteIsRejectedTest()
    {
        client.get().uri(PRIVATE_PATH).header(HttpHeaders.AUTHORIZATION, bareJwt()).exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, value -> value.contains("invalid_token"));
    }

    @Test
    void unlistedTenantHeaderOnPublicRouteIsRejectedTest()
    {
        client.get().uri(PUBLIC_PATH).header(X_TENANT, "unknown-realm").exchange()
                .expectStatus().isBadRequest();
    }

    private static String bareJwt()
    {
        return MockKeycloakServer.sign(new JWTClaimsSet.Builder()
                .issuer(MockKeycloakServer.issuerPrefix() + "techsophy-platform")
                .subject("user")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build());
    }
}
