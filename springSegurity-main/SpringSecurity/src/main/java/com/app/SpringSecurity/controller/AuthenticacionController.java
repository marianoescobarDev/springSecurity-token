package com.app.SpringSecurity.controller;
import com.app.SpringSecurity.controller.dto.AuthCreateUser;
import com.app.SpringSecurity.controller.dto.AuthLoginRequest;
import com.app.SpringSecurity.controller.dto.AuthResponse;
import com.app.SpringSecurity.service.UserDetailsServiceImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/auth")
public class AuthenticacionController {


    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @PostMapping("/sign-up")
    public ResponseEntity<AuthResponse> registrarse(@RequestBody @Valid AuthCreateUser authCreateUser){
        return new ResponseEntity<>(this.userDetailsService.createUser(authCreateUser),HttpStatus.CREATED);
    }

    @PostMapping("/log-in")
    public ResponseEntity<AuthResponse>login(@RequestBody @Valid AuthLoginRequest authLoginRequest){
        return new ResponseEntity<>(this.userDetailsService.loginUser(authLoginRequest), HttpStatus.OK);
    }


}
