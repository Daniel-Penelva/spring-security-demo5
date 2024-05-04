package com.restapi.springsecuritydemo5.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity                                           // Habilita a segurança web do Spring Security na aplicação.
@EnableMethodSecurity                                        // Habilita a segurança baseada em métodos do Spring Security.
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final CustomBasicAuthenticationFilter customBasicAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())                                                                                  // Desabilita a proteção CSRF (Cross-Site Request Forgery)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))                     // Define a política de gerenciamento de sessão como STATELESS, o que significa que a aplicação não manterá estado de sessão
                .authorizeHttpRequests((request) -> request
                        .requestMatchers(HttpMethod.POST, "/user/**").permitAll()                                     // Permite que requisições do tipo POST para o endpoint "/user" sejam acessíveis sem autenticação
                        .anyRequest().authenticated()                                                                             // Exige autenticação para qualquer outra requisição
                ).addFilterBefore(customBasicAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)       // Define a cadeia de filtros
                .build();
    }
}

/*Essa classe é responsável por configurar as regras de segurança da aplicação web, desabilitando CSRF, definindo a política de sessão como 
 * STATELESS, configurando permissões de acesso aos endpoints e adicionando o filtro de autenticação básica personalizado na cadeia de filtros 
 * do Spring Security.
 * */