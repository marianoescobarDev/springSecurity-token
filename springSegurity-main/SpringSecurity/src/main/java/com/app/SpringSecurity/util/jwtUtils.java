package com.app.SpringSecurity.util;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class jwtUtils {

    @Value("${security-privatekey-jwt}")
    private String securityKey;

    @Value("${security-privateUser-jwt}")
    private String securityUser;

    public String crearToken(Authentication authentication){
        Algorithm algorithm = Algorithm.HMAC256(this.securityKey);
        String usuario = authentication.getPrincipal().toString();

        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String jwtToken = JWT.create()
                .withIssuer(this.securityUser)
                .withSubject(usuario)
                .withClaim("permisos", authorities)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis()+ 1800000))
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(new Date(System.currentTimeMillis()))
                .sign(algorithm);

        return jwtToken;
    }


    public DecodedJWT validarToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.securityKey);

            JWTVerifier verificadorToken = JWT.require(algorithm)
                    .withIssuer(this.securityUser)
                    .build();

            DecodedJWT decodedJWT = verificadorToken.verify(token);

            return decodedJWT;

        }catch (JWTVerificationException exception) {
            throw new JWTVerificationException("token invalido NOT AUTHORIZED");
        }

    }

    public String extraerUsuario (DecodedJWT decodedJWT){
        return decodedJWT.getSubject().toString();
    }
    public Claim extraerClaimEspecif(DecodedJWT decodedJWT , String claimName){
        return decodedJWT.getClaim(claimName);
    }

    public Map<String,Claim> extraerTodosClaim(DecodedJWT decodedJWT){
        return decodedJWT.getClaims();

    }

}
