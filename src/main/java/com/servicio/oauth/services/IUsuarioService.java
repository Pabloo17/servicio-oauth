package com.servicio.oauth.services;

import com.servicio.commons.models.entity.Usuario;

public interface IUsuarioService {

  public Usuario findByUserName(String username);

  public Usuario update(Usuario usuario, Long id);
}
