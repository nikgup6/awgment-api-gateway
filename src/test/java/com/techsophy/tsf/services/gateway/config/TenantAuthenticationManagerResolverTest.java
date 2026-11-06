package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import com.techsophy.tsf.services.gateway.support.MockKeycloakServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
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
@ExtendWith({MockitoExtension.class, OutputCaptureExtension.class})
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
    void toTenantLogsMaskedNonJwtHeaderTest(CapturedOutput output)
    {
        ServerWebExchange exchange = exchange("Basic dXNlcjpwYXNzd29yZA==");
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,
                Route.async().id("dms-public").uri("http://dms").predicate(e -> true).build());
        Assertions.assertNull(TenantAuthenticationManagerResolver.toTenant(exchange));
        Assertions.assertTrue(output.getOut().contains(
                "Public request on route dms-public (GET) has an Authorization header 'Basic ****' that is not a Bearer token"));
        Assertions.assertFalse(output.getOut().contains("dXNlcjpwYXNzd29yZA"));
        Assertions.assertFalse(output.getErr().contains("ParseException"));
    }

    @Test
    void toTenantIgnoresBareJwtTest(CapturedOutput output)
    {
        // a well formed JWT without the Bearer scheme is never verified, so its issuer must not become the tenant
        String bareJwt = sign(claims(TENANT));
        Assertions.assertNull(TenantAuthenticationManagerResolver.toTenant(exchange(bareJwt)));
        Assertions.assertTrue(output.getOut().contains("has an Authorization header '****' that is not a Bearer token"));
        Assertions.assertFalse(output.getOut().contains(bareJwt));
        Assertions.assertEquals(TENANT, TenantAuthenticationManagerResolver.toTenant(exchange("Bearer " + bareJwt)));
    }

    @Test
    void maskAuthorizationTest()
    {
        Assertions.assertEquals("Basic ****", TenantAuthenticationManagerResolver.maskAuthorization("Basic dXNlcjpwYXNz"));
        Assertions.assertEquals("Bearer ****", TenantAuthenticationManagerResolver.maskAuthorization("Bearer abc"));
        // no scheme: the whole value may be a credential
        Assertions.assertEquals("****", TenantAuthenticationManagerResolver.maskAuthorization("dXNlcjpwYXNz"));
        Assertions.assertEquals("****", TenantAuthenticationManagerResolver.maskAuthorization("secret:value rest"));
    }

    @Test
    void resolveMalformedTokenTest()
    {
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer abc")), HttpStatus.UNAUTHORIZED);
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer aaa.bbb.ccc")), HttpStatus.UNAUTHORIZED);
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
    void authenticateUnlistedRealmTest(CapturedOutput output)
    {
        // the realm exists on the configured Keycloak but is not in tenants.registrations
        assertStatus(authenticate(sign(claims("techsophy-platform"))), HttpStatus.UNAUTHORIZED);
        Assertions.assertTrue(output.getOut().contains(
                "Bearer token for realm 'techsophy-platform' on GET /api/core is not in tenants.registrations; rejected with 401"));
    }

    @Test
    void pathPrefixTest()
    {
        Assertions.assertEquals("/api/d", TenantAuthenticationManagerResolver.pathPrefix(
                MockServerWebExchange.from(MockServerHttpRequest.get("/api/d/secretcode"))));
        Assertions.assertEquals("/api", TenantAuthenticationManagerResolver.pathPrefix(
                MockServerWebExchange.from(MockServerHttpRequest.get("/api"))));
    }

    @Test
    void authenticateRealmsFromYamlListTest()
    {
        TenantRegistration tenantRegistration = new TenantRegistration();
        tenantRegistration.setRegistrations(List.of(TENANT, " KIMS "));
        ReflectionTestUtils.setField(tenantAuthenticationManagerResolver,"tenants",tenantRegistration);
        StepVerifier.create(authenticate(sign(claims("KIMS"))))
                .assertNext(authentication -> Assertions.assertTrue(authentication.isAuthenticated()))
                .verifyComplete();
        assertStatus(authenticate(sign(claims("techsophy-platform"))), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void resolveWithoutRegistrationsTest()
    {
        ReflectionTestUtils.setField(tenantAuthenticationManagerResolver,"tenants",new TenantRegistration());
        assertStatus(tenantAuthenticationManagerResolver.resolve(exchange("Bearer " + sign(claims(TENANT)))), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticateInvalidSignatureTest()
    {
        String[] token = sign(claims(TENANT)).split("\\.");
        String[] otherToken = sign(claims(TENANT).subject("someone-else")).split("\\.");
        assertStatus(authenticate(token[0] + "." + otherToken[1] + "." + token[2]), HttpStatus.UNAUTHORIZED);
        assertStatus(authenticate(new PlainJWT(claims(TENANT).build()).serialize()), HttpStatus.UNAUTHORIZED);
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
                        ((ResponseStatusException) e).getStatusCode()))
                .verify();
    }
}
