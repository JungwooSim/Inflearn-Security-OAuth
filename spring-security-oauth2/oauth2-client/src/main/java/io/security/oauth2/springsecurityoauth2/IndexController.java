package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @GetMapping("/")
  public String index() {

    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

    String clientId = clientRegistration.getClientId();
    System.out.println("clientId = " + clientId);

    String redirectUri = clientRegistration.getRedirectUri();
    System.out.println("redirectUri = " + redirectUri);
    return "index";
  }

  /**
   * spring mvc 에서 인증 객체 참조
   */
  @GetMapping("/user")
  public OAuth2User user(Authentication authentication) {
    OAuth2AuthenticationToken authentication2 = (OAuth2AuthenticationToken) authentication;
    OAuth2User oAuth2User = authentication2.getPrincipal();
    return oAuth2User;
  }

  /**
   * spring mvc 에서 인증 객체 참조
   */
  @GetMapping("/oauth2User")
  public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
    return oAuth2User;
  }

  /**
   * spring mvc 에서 인증 객체 참조
   */
  @GetMapping("/oidcUser")
  public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
    return oidcUser;
  }
}
