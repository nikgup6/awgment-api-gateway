package com.techsophy.tsf.services.gateway.repository;

import com.techsophy.tsf.services.gateway.dto.TenantRegistration;
import com.techsophy.tsf.services.gateway.service.KeycloakClientCredentialsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Slf4j
public class KeycloakRealmRepository implements ReactiveClientRegistrationRepository,Iterable<ClientRegistration>
{
    @Autowired
    private TenantRegistration tenants;

    @Value("${keycloak.client.id}")
    private String clientId;

    @Value("${keycloak.issuer-uri}")
    private String keycloakIssuerURI;

    @Autowired
    private KeycloakClientCredentialsService service;

    private Map<String, ClientRegistration> registrationMap;
    private List<String> registrationsList;
    @Override
    public Iterator<ClientRegistration> iterator()
    {
        String registrations=tenants.getRegistrations().get(0);
        log.info("Tenant Names : "+registrations);
        registrationsList= List.of(registrations.split(","));
        registrationMap = registrationsList.parallelStream().map(s -> OidcClientRegistrations
                .fromOidcIssuerLocation(keycloakIssuerURI+s)
                .registrationId(s).clientName(s).clientId(clientId).build()).collect(
                Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> clientRegistration
                ));
        return new ArrayList<>(registrationMap.values()).iterator();
    }

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId)
    {
        return registrationsList.stream().filter(s -> s.equals(registrationId)).map(s ->
                Mono.fromCallable(() ->{
                    String secret;
                    try
                    {
                       secret= service.fetchClientDetails(s, false);
                    }
                    catch (Exception e)
                    {
                        log.error(e.getMessage());
                        secret=service.fetchClientDetails(s,true);
                    }
                    return ClientRegistration.withClientRegistration(registrationMap.get(s))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .clientSecret(secret)
                            .build();
                })).findFirst().orElseThrow();
    }
}
