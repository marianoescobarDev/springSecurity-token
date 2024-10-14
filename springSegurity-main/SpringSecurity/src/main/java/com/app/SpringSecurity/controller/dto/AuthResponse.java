package com.app.SpringSecurity.controller.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"usuario","mensaje","jwt","status" })
public record AuthResponse (String usuario,
                            String mensaje,
                            String jwt,
                            boolean status){
}
