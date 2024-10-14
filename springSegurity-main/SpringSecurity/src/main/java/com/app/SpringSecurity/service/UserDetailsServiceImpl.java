package com.app.SpringSecurity.service;


import com.app.SpringSecurity.controller.dto.AuthCreateUser;
import com.app.SpringSecurity.controller.dto.AuthLoginRequest;
import com.app.SpringSecurity.controller.dto.AuthResponse;
import com.app.SpringSecurity.persistencia.entidades.niveles;
import com.app.SpringSecurity.persistencia.entidades.usuarios;
import com.app.SpringSecurity.repository.nivelRepository;
import com.app.SpringSecurity.repository.usuarioRepository;
import com.app.SpringSecurity.util.jwtUtils;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private jwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private usuarioRepository usuarioRepository;

    @Autowired
    private nivelRepository nivelRepository;


    @Override
    public UserDetails loadUserByUsername(String nombre) throws UsernameNotFoundException {
        usuarios usuario = usuarioRepository.findUsuarioByNombre(nombre)
                .orElseThrow(()-> new UsernameNotFoundException("El usuario " + nombre + " no se encontro"));

        List<SimpleGrantedAuthority> authorityList = new LinkedList<>();
        usuario.getNiveles()
                .forEach(niveles -> authorityList.add(new SimpleGrantedAuthority("ROLE_" .concat(niveles.getRoleEnum().name()))));
        usuario.getNiveles().stream()
                .flatMap(niveles ->  niveles.getPermisos().stream())
                .forEach(permisos -> authorityList.add(new SimpleGrantedAuthority(permisos.getNombre())));

        return new User(usuario.getNombre(),
                usuario.getClave(),
                usuario.isEnable(),
                usuario.isAccountNoExpired(),
                usuario.isAccountNoLocked(),
                usuario.isCredentialNoExpired(),
                authorityList
                );
    }

    public AuthResponse loginUser (AuthLoginRequest authLoginRequest){
        String usuario = authLoginRequest.usuario();
        String clave = authLoginRequest.clave();
        Authentication authentication = this.authenticate(usuario, clave);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accesoToken =  jwtUtils.crearToken(authentication);

        AuthResponse authResponse =  new AuthResponse(usuario, "Usuario logeado correctamente ", accesoToken,true);
        return  authResponse;
    }

    private Authentication authenticate(String usuario, String clave) {
        UserDetails userDetails = this.loadUserByUsername(usuario);
        if(userDetails==null){
            throw new BadCredentialsException("usuario o clave invalido  ");
        }

        if(!passwordEncoder.matches(clave, userDetails.getPassword())){
            throw new BadCredentialsException("usuario o clave invalido");
        }
        return new UsernamePasswordAuthenticationToken(usuario,userDetails.getPassword(), userDetails.getAuthorities());
    }

    public AuthResponse createUser(@Valid AuthCreateUser authCreateUser) {
        String username = authCreateUser.usuario();
        String clave = authCreateUser.clave();
        List<String>nivelRequest = authCreateUser.roleRequest().roleListName();
        Set<niveles> nivelesSet = nivelRepository.findNivelesByroleEnumIn(nivelRequest).stream().collect(Collectors.toSet());

        if(nivelesSet.isEmpty()){
            throw new IllegalArgumentException("Los roles especificados no existen");
        }

        usuarios usuario = usuarios.builder()
                .nombre(username)
                .clave(passwordEncoder.encode(clave))
                .niveles(nivelesSet)
                .isEnable(true)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialNoExpired(true)
                .build();
        usuarios usuariocreado = usuarioRepository.save(usuario);

        List<SimpleGrantedAuthority>authorityList = new ArrayList<>();

        usuariocreado.getNiveles().forEach(nivel -> authorityList.add(new SimpleGrantedAuthority("ROLE_" .concat(nivel.getRoleEnum().name()))));

        usuariocreado.getNiveles()
                .stream()
                .flatMap(role -> role.getPermisos().stream())
                .forEach(permisos -> authorityList.add(new SimpleGrantedAuthority(permisos.getNombre())));

//*        SecurityContext securityContext = SecurityContextHolder.getContext();*//*
        Authentication authentication =  new UsernamePasswordAuthenticationToken(usuariocreado.getNombre(), usuariocreado.getClave(),authorityList);
        String accesotoken = jwtUtils.crearToken(authentication);
        AuthResponse authResponse = new AuthResponse(usuariocreado.getNombre(),"usuario creado correctamente",accesotoken,true);

        return authResponse;

    }
}
