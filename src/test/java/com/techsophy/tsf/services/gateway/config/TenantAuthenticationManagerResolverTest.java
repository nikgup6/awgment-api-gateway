package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import com.techsophy.tsf.services.gateway.support.MockKeycloakServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.TEST_ACTIVE_PROFILE;

@ActiveProfiles(TEST_ACTIVE_PROFILE)
@SpringBootTest(properties = {"CORS_ALLOWEDORIGINS=VALUE", "ADD_ALLOWEDMETHOD=VALUE2", "ADD_ALLOWEDHEADER=VALUE3"})
class TenantAuthenticationManagerResolverTest {

    static String idToken = "Bearer eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJmZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNnspA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcipR2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2macAAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOYu0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl6cQQWNiDpWOl_lxXjQEvQ";
    static final String TENANT = "medunited";

    @InjectMocks
    TenantAuthenticationManagerResolver tenantAuthenticationManagerResolver;

    @DynamicPropertySource
    static void keycloakProperties(DynamicPropertyRegistry registry)
    {
        registry.add("keycloak.issuer-uri", MockKeycloakServer::issuerPrefix);
    }

    @BeforeEach
    public void setUp()
    {
        TenantRegistration tenantRegistration = new TenantRegistration();
        tenantRegistration.setRegistrations(List.of(TENANT + ",KIMS," + MockKeycloakServer.MISSING_REALM + "," + MockKeycloakServer.NO_KEYS_REALM));
        ReflectionTestUtils.setField(tenantAuthenticationManagerResolver,"keycloakIssuerUri",MockKeycloakServer.issuerPrefix());
        ReflectionTestUtils.setField(tenantAuthenticationManagerResolver,"tenants",tenantRegistration);
    }

    @Test
    void getIssuerFromTokenTest() throws ParseException
    {
        Assertions.assertEquals("server.example.com",
                TenantAuthenticationManagerResolver.getIssuerFromToken(idToken));
        Assertions.assertEquals("server.example.com",
                TenantAuthenticationManagerResolver.getIssuerFromToken(idToken.replace("Bearer ", "bearer ")));
    }

    @Test
    void getIssuerFromTokenWithMalformedTokenTest()
    {
        Assertions.assertThrows(ParseException.class, () ->
                TenantAuthenticationManagerResolver.getIssuerFromToken("Bearer abc"));
    }

    @Test
    void toTenantTest()
    {
        Assertions.assertNull(TenantAuthenticationManagerResolver.toTenant(exchange(null)));
        Assertions.assertNull(TenantAuthenticationManagerResolver.toTenant(exchange("Bearer abc")));
        Assertions.assertEquals("server.example.com", TenantAuthenticationManagerResolver.toTenant(exchange(idToken)));
    }

    @Test
    void resolveMalformedTokenTest()
    {
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer abc")), HttpStatus.FORBIDDEN);
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer aaa.bbb.ccc")), HttpStatus.FORBIDDEN);
    }

    @Test
    void resolveInvalidTenantTest()
    {
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange(idToken)), HttpStatus.UNAUTHORIZED);
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer " + sign(claims(TENANT).issuer(null)))),
                HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticateValidTokenTest()
    {
        StepVerifier.create(authenticate(sign(claims(TENANT))))
                .assertNext(authentication -> Assertions.assertTrue(authentication.isAuthenticated()))
                .verifyComplete();
    }

    @Test
    void authenticateInvalidSignatureTest()
    {
        String[] token = sign(claims(TENANT)).split("\\.");
        String[] otherToken = sign(claims(TENANT).subject("someone-else")).split("\\.");
        assertStatus(authenticate(token[0] + "." + otherToken[1] + "." + token[2]), HttpStatus.FORBIDDEN);
        assertStatus(authenticate(new PlainJWT(claims(TENANT).build()).serialize()), HttpStatus.FORBIDDEN);
    }

    @Test
    void authenticateExpiredTokenTest()
    {
        assertStatus(authenticate(sign(claims(TENANT).expirationTime(Date.from(Instant.now().minusSeconds(600))))),
                HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticateIssuerMismatchTest()
    {
        assertStatus(authenticate(sign(claims(TENANT).issuer("https://other.example.com/auth/realms/" + TENANT))),
                HttpStatus.UNAUTHORIZED);
    }

    @Test
    void resolveKeycloakConfigurationUnavailableTest()
    {
        assertServiceUnavailable(tenantAuthenticationManagerResolver.resolve(
                exchange("Bearer " + sign(claims(MockKeycloakServer.MISSING_REALM)))));
    }

    @Test
    void authenticateSigningKeysUnavailableTest()
    {
        assertServiceUnavailable(authenticate(sign(claims(MockKeycloakServer.NO_KEYS_REALM))));
    }

    private Mono<Authentication> authenticate(String token)
    {
        return tenantAuthenticationManagerResolver.resolve(exchange("Bearer " + token))
                .flatMap(manager -> manager.authenticate(new BearerTokenAuthenticationToken(token)));
    }

    private static JWTClaimsSet.Builder claims(String tenant)
    {
        return new JWTClaimsSet.Builder()
                .issuer(MockKeycloakServer.issuerPrefix() + tenant)
                .subject("user")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)));
    }

    private static String sign(JWTClaimsSet.Builder claims)
    {
        return MockKeycloakServer.sign(claims.build());
    }

    private static ServerWebExchange exchange(String authorization)
    {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/core/x");
        if (authorization != null)
        {
            request.header("Authorization", authorization);
        }
        return MockServerWebExchange.from(request);
    }

    private static void assertStatus(Mono<?> result, HttpStatus status)
    {
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> Assertions.assertEquals(status,
                        ((BearerTokenError) ((OAuth2AuthenticationException) e).getError()).getHttpStatus()))
                .verify();
    }

    private static void assertServiceUnavailable(Mono<?> result)
    {
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE,
                        ((ResponseStatusException) e).getStatus()))
                .verify();
    }
}
