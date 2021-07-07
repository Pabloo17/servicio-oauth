package com.servicio.oauth.security.event;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

  @Override
  public void publishAuthenticationSuccess(Authentication authentication) {
    UserDetails user = (UserDetails) authentication.getPrincipal();
    log.info("Success login: ".concat(user.getUsername()));
  }

  @Override
  public void publishAuthenticationFailure(
      AuthenticationException exception, Authentication authentication) {
    log.error("Error en el login: ".concat(exception.getMessage()));
  }
}
