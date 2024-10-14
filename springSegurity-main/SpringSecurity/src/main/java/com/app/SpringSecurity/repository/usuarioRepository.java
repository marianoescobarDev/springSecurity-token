package com.app.SpringSecurity.repository;

import com.app.SpringSecurity.persistencia.entidades.usuarios;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface usuarioRepository extends CrudRepository<usuarios,Long> {

    Optional<usuarios> findUsuarioByNombre(String nombre);


}
