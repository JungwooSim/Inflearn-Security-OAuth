package io.security.oauth2.authorization2;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
    httpSecurity.exceptionHandling(exception -> exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
    httpSecurity.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    return httpSecurity.build();
  }

  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder().issuer("http://localhost:9000").build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
     .clientId("oauth2-client-app")
     .clientSecret("{noop}secret")
     .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
     .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
     .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
     .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
     .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
     .redirectUri("http://127.0.0.1:8081")
     .scope(OidcScopes.OPENID)
     .scope("read")
     .scope("write")
     .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
     .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
    RSAKey rsaKey = generateRas();
    JWKSet jwkSet = new JWKSet(rsaKey);

    return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
  }

  private RSAKey generateRas() throws NoSuchAlgorithmException {
    KeyPair keyPair = generateRsaKey();
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    return new RSAKey.Builder(rsaPublicKey)
     .privateKey(rsaPrivateKey)
     .keyID(UUID.randomUUID().toString())
     .build();
  }

  private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }
}
