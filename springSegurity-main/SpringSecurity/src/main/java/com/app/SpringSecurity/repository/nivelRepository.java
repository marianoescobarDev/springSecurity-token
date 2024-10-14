package com.app.SpringSecurity.repository;

import com.app.SpringSecurity.persistencia.entidades.niveles;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface nivelRepository extends CrudRepository<niveles,Long> {
    List<niveles> findNivelesByroleEnumIn(List<String> nivelesRoleEnum);
}
