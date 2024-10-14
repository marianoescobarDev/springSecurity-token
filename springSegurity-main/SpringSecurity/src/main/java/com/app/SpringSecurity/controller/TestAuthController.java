package com.app.SpringSecurity.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/method")
//@PreAuthorize("denyAll()")
public class TestAuthController {

    @GetMapping("/hello")
    //@PreAuthorize("permitAll()")
    public String hello(){
        return "hello world";
    }

    @GetMapping("/get")
    //@PreAuthorize("hasAuthority('READ')")
    public String helloSecuredGet(){
        return "hello world secured - GET";
    }

    @PatchMapping("/patch")
    //@PreAuthorize("hasAuthority('REFACTOR')")
    public String helloSecuredPatch(){
        return "hello world secured - PATCH";
    }

    @DeleteMapping("/delete")
    //@PreAuthorize("hasAuthority('DELETE')")
    public String helloSecuredDelete(){
        return "hello world secured - DELETE";
    }

    @PutMapping("/put")
    //@PreAuthorize("hasAuthority('UPDATE')")
    public String helloSecuredPut(){
        return "hello world secured - PUT";
    }

    @PostMapping("/post")
    //@PreAuthorize("hasAuthority('CREATE')")
    public String helloSecured(){
        return "hello world secured - POST";
    }

}
