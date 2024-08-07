package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
public class OAuth2ClientConfig {

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
  }

  private ClientRegistration keycloakClientRegistration() {
    return ClientRegistrations.fromIssuerLocation("http://localhost:8085/realms/oauth2")
     .registrationId("keycloak")
     .clientId("oauth2-client-app")
     .clientSecret("w2SOF9Ye0iFuQPA2pRuGDJvvFKOXG9dF")
     .redirectUri("http://localhost:8081/login/oauth2/code/keyclock")
     .build();
  }
}
