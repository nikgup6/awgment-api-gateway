package com.techsophy.tsf.services.gateway.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * In-process stand-in for Keycloak's OpenID discovery endpoint, shared by the tests so they do not depend on
 * an external Keycloak. Known realms serve the recorded Keycloak 26 document, except "legacy" (no nested
 * objects, as older Keycloak versions publish) and "mismatch" (wrong issuer); any other realm is a 404.
 * Known realms also publish the public key of {@link #sign(JWTClaimsSet)} on their JWKS endpoint, except "nokeys"
 * (JWKS endpoint is a 404, as when Keycloak fails after discovery).
 */
public final class MockKeycloakServer
{
    public static final String LEGACY_REALM = "legacy";
    public static final String MISMATCH_REALM = "mismatch";
    public static final String MISSING_REALM = "missing";
    public static final String NO_KEYS_REALM = "nokeys";
    private static final Set<String> KNOWN_REALMS = Set.of("medunited", "techsophy-platform", "KIMS", LEGACY_REALM, MISMATCH_REALM, NO_KEYS_REALM);

    private static final Pattern DISCOVERY_PATH = Pattern.compile("^/auth/realms/([^/]+)/\\.well-known/openid-configuration$");
    private static final Pattern CERTS_PATH = Pattern.compile("^/auth/realms/([^/]+)/protocol/openid-connect/certs$");
    private static final RSAKey SIGNING_KEY = generateKey();
    private static String issuerPrefix;

    private MockKeycloakServer()
    {
    }

    /** Starts the server on first use and returns e.g. "http://127.0.0.1:PORT/auth/realms/". */
    public static synchronized String issuerPrefix()
    {
        if (issuerPrefix == null)
        {
            issuerPrefix = start();
        }
        return issuerPrefix;
    }

    public static String keycloak26Document(String issuer)
    {
        try (InputStream in = MockKeycloakServer.class.getResourceAsStream("/oidc/keycloak26-openid-configuration.json"))
        {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("{{ISSUER}}", issuer);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }

    /** Returns an RS256 token signed with the key every known realm publishes, as Keycloak would issue it. */
    public static String sign(JWTClaimsSet claims)
    {
        try
        {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SIGNING_KEY.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(SIGNING_KEY));
            return jwt.serialize();
        }
        catch (JOSEException e)
        {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generateKey()
    {
        try
        {
            return new RSAKeyGenerator(2048).keyID("mock-keycloak").generate();
        }
        catch (JOSEException e)
        {
            throw new IllegalStateException(e);
        }
    }

    private static String start()
    {
        try
        {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            String prefix = "http://127.0.0.1:" + server.getAddress().getPort() + "/auth/realms/";
            server.createContext("/", exchange -> {
                Matcher m = DISCOVERY_PATH.matcher(exchange.getRequestURI().getPath());
                Matcher certs = CERTS_PATH.matcher(exchange.getRequestURI().getPath());
                String realm = m.matches() ? m.group(1) : MISSING_REALM;
                byte[] body = new byte[0];
                if (certs.matches())
                {
                    if (KNOWN_REALMS.contains(certs.group(1)) && !NO_KEYS_REALM.equals(certs.group(1)))
                    {
                        body = new JWKSet(SIGNING_KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
                    }
                }
                else if (KNOWN_REALMS.contains(realm))
                {
                    String issuer = prefix + (MISMATCH_REALM.equals(realm) ? "someone-else" : realm);
                    String document = keycloak26Document(issuer);
                    if (LEGACY_REALM.equals(realm))
                    {
                        document = document.replaceAll(",?\\s*\"mtls_endpoint_aliases\"\\s*:\\s*\\{[^}]*}", "");
                    }
                    body = document.getBytes(StandardCharsets.UTF_8);
                }
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(body.length == 0 ? 404 : 200, body.length == 0 ? -1 : body.length);
                if (body.length > 0)
                {
                    exchange.getResponseBody().write(body);
                }
                exchange.close();
            });
            server.setExecutor(null);
            server.start();
            return prefix;
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }
}
