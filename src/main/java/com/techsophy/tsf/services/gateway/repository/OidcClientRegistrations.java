package com.techsophy.tsf.services.gateway.repository;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Same result as Spring Security 5.3's ClientRegistrations.fromOidcIssuerLocation, but the discovery
 * document is parsed from its raw JSON text. Spring Security 5.3 converts it to a Map first, which leaves
 * nested objects (such as Keycloak 26's mtls_endpoint_aliases) as plain maps that Nimbus 7 rejects.
 */
public final class OidcClientRegistrations
{
    private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";
    private static final RestTemplate rest = new RestTemplate();

    private OidcClientRegistrations()
    {
    }

    public static ClientRegistration.Builder fromOidcIssuerLocation(String issuer)
    {
        Assert.hasText(issuer, "issuer cannot be empty");
        URI issuerUri = URI.create(issuer);
        URI uri = UriComponentsBuilder.fromUri(issuerUri)
                .replacePath(issuerUri.getPath() + OIDC_METADATA_PATH).build(Collections.emptyMap());
        OIDCProviderMetadata metadata;
        try
        {
            String body = rest.getForObject(uri, String.class);
            if (body == null)
            {
                throw new ParseException("Empty OpenID configuration response");
            }
            metadata = OIDCProviderMetadata.parse(body);
        }
        catch (ParseException | RestClientException e)
        {
            throw new IllegalArgumentException("Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"", e);
        }
        String metadataIssuer = metadata.getIssuer().getValue();
        if (!issuer.equals(metadataIssuer))
        {
            throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the configuration metadata did "
                    + "not match the requested issuer \"" + issuer + "\"");
        }
        List<GrantType> grantTypes = metadata.getGrantTypes();
        if (grantTypes != null && !grantTypes.contains(GrantType.AUTHORIZATION_CODE))
        {
            throw new IllegalArgumentException("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + issuer
                    + "\" returned a configuration of " + grantTypes);
        }
        Map<String, Object> configurationMetadata = new LinkedHashMap<>(metadata.toJSONObject());
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(issuerUri.getHost())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .scope(getScopes(metadata))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(getClientAuthenticationMethod(issuer, metadata))
                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
                .authorizationUri(metadata.getAuthorizationEndpointURI().toASCIIString())
                .providerConfigurationMetadata(configurationMetadata)
                .tokenUri(metadata.getTokenEndpointURI().toASCIIString())
                .clientName(issuer)
                .jwkSetUri(metadata.getJWKSetURI().toASCIIString());
        if (metadata.getUserInfoEndpointURI() != null)
        {
            builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
        }
        return builder;
    }

    private static ClientAuthenticationMethod getClientAuthenticationMethod(String issuer, OIDCProviderMetadata metadata)
    {
        List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> methods = metadata.getTokenEndpointAuthMethods();
        if (methods == null || methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
        {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
        if (methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST))
        {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }
        if (methods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE))
        {
            return ClientAuthenticationMethod.NONE;
        }
        throw new IllegalArgumentException("Only ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST and "
                + "ClientAuthenticationMethod.NONE are supported. The issuer \"" + issuer + "\" returned a configuration of " + methods);
    }

    private static List<String> getScopes(OIDCProviderMetadata metadata)
    {
        Scope scope = metadata.getScopes();
        return scope == null ? Collections.singletonList(OidcScopes.OPENID) : scope.toStringList();
    }
}
