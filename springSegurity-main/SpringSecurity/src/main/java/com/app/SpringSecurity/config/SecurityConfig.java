package com.app.SpringSecurity.config;

import com.app.SpringSecurity.config.filter.JwtFilterValidator;
import com.app.SpringSecurity.service.UserDetailsServiceImpl;
import com.app.SpringSecurity.util.jwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.LinkedList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private jwtUtils jwtUtils;

    /*filtros de seguridad*/

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf-> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http-> {

                    //*endpoints publicos *//*
                    http.requestMatchers(HttpMethod.POST,"/auth/**").permitAll();

                    //*endpoints privados*//*
                    http.requestMatchers(HttpMethod.POST,"/method/post").hasAuthority("CREATE");
                    http.requestMatchers(HttpMethod.GET,"/method/get").hasAuthority("READ");
                    http.requestMatchers(HttpMethod.PATCH,"/method/patch").hasAuthority("REFACTOR");

                    //*enpoints no especificados*//*

                    http.anyRequest().denyAll(); //* Deniega todos los no especificados*//*
                    //* http.anyRequest().authenticated(); Debe autenticarse  para todos los no especificados*//*

                })
                .addFilterBefore(new JwtFilterValidator(jwtUtils), BasicAuthenticationFilter.class)
                .build();
    }

    /*filtros de seguridad*/
 /*   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf-> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }*/



    /*manejo de auntenticadores*/
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*para conectarse a la base de datos*/
    @Bean
    public AuthenticationProvider authenticationProvider (UserDetailsServiceImpl userDetailsService){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }



    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /*usuarios en memoria*/
   /* @Bean
    public UserDetailsService userDetailsService (){
        List<UserDetails> userDetailsList =  new LinkedList<>();
        userDetailsList.add(User.withUsername("dev")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ","CREATE")
                .build()
        );
        userDetailsList.add(User.withUsername("qa")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ" )
                .build()
        );

        return new InMemoryUserDetailsManager(userDetailsList);
    }*/



}
