package com.app.SpringSecurity.controller.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

public record AuthCreateUser (@NotBlank String usuario,
                              @NotBlank String clave ,
                              @Valid  AuthCreateRoleRequest roleRequest) {

}
