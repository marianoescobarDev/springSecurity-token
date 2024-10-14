package com.app.SpringSecurity.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record AuthLoginRequest (@NotBlank String usuario,
                                @NotBlank String clave){

}
