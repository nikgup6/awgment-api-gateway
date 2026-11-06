package com.techsophy.tsf.services.gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.web.server.ServerWebExchange;
import reactor.test.StepVerifier;
import static com.techsophy.tsf.services.gateway.constants.GatewayConstants.BEARER_SCHEME_MISSING;

class StrictBearerTokenConverterTest
{
    static final String JWT = new PlainJWT(new JWTClaimsSet.Builder().issuer("http://keycloak/auth/realms/medunited").build()).serialize();

    StrictBearerTokenConverter converter = new StrictBearerTokenConverter();

    @Test
    void bareJwtIsRejectedTest()
    {
        StepVerifier.create(converter.convert(exchange(JWT)))
                .expectErrorSatisfies(e -> {
                    BearerTokenError error = (BearerTokenError) ((OAuth2AuthenticationException) e).getError();
                    Assertions.assertEquals(HttpStatus.UNAUTHORIZED, error.getHttpStatus());
                    Assertions.assertEquals("invalid_token", error.getErrorCode());
                    Assertions.assertEquals(BEARER_SCHEME_MISSING, error.getDescription());
                })
                .verify();
    }

    @Test
    void bearerTokenIsConvertedTest()
    {
        StepVerifier.create(converter.convert(exchange("Bearer " + JWT)))
                .assertNext(token -> Assertions.assertEquals(JWT, ((BearerTokenAuthenticationToken) token).getToken()))
                .verifyComplete();
    }

    @Test
    void otherHeadersAreNotCredentialsTest()
    {
        StepVerifier.create(converter.convert(exchange(null))).verifyComplete();
        StepVerifier.create(converter.convert(exchange("Basic dXNlcjpwYXNz"))).verifyComplete();
        // not a JWT, so not a bare token either: left for the downstream service, as before
        StepVerifier.create(converter.convert(exchange("someapikey"))).verifyComplete();
        StepVerifier.create(converter.convert(exchange("aaa.bbb.ccc"))).verifyComplete();
    }

    private static ServerWebExchange exchange(String authorization)
    {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/config-server/x");
        if (authorization != null)
        {
            request.header("Authorization", authorization);
        }
        return MockServerWebExchange.from(request);
    }
}
