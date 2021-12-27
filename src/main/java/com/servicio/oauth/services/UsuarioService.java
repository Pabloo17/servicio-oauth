package com.servicio.oauth.services;

import java.util.List;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.servicio.commons.models.entity.Usuario;
import com.servicio.oauth.clients.UsuarioFeignClient;
import brave.Tracer;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;

// interfaz propia de spring security que obtiene el usuario a partir de su nombre
@Slf4j
@Service
public class UsuarioService implements IUsuarioService, UserDetailsService {

  @Autowired private UsuarioFeignClient client;

  @Autowired private Tracer tracer;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    try {

      Usuario usuario = client.findByUserName(username);

      // GrantedAuthority= roles de spring security
      List<GrantedAuthority> authorities =
          usuario
              .getRoles()
              .stream()
              .map(role -> new SimpleGrantedAuthority(role.getNombre()))
              .peek(authority -> log.info("Role: ".concat(authority.getAuthority())))
              .collect(Collectors.toList());

      log.info("Usuario autentificado ".concat(username));

      return new User(
          usuario.getUsername(),
          usuario.getPassword(),
          usuario.isEnabled(),
          true,
          true,
          true,
          authorities);
    } catch (FeignException e) {

      String error = "Error en el login, no existe el usuario '" + username + "' en el sistema";
      log.error(error);

      tracer.currentSpan().tag("error.mensaje", error.concat(": ").concat(e.getMessage()));
      throw new UsernameNotFoundException(
          "Error en el login, no existe el usuario '" + username + "' en el sistema");
    }
  }

  @Override
  public Usuario findByUserName(String username) {

    return client.findByUserName(username);
  }
}
