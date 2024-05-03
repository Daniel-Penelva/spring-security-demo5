package com.restapi.springsecuritydemo5.security;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.restapi.springsecuritydemo5.user.User;

import lombok.Getter;

@Getter
public class UserPrincipal {
    
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    private UserPrincipal(User user){
        this.username = user.getUsername();
        this.password = user.getPassword();

        this.authorities = user.getRoles().stream().map(role -> {
            return new SimpleGrantedAuthority("ROLE_".concat(role.getName()));
        }).collect(Collectors.toList());
    }

    public static UserPrincipal create(User user){
        return new UserPrincipal(user);
    }
}

/* A classe UserPrincipal é uma implementação da interface UserDetails do Spring Security. Ela é responsável por encapsular as informações do 
 * usuário autenticado, incluindo o nome de usuário, senha e as autoridades (permissões) atribuídas a esse usuário.
 * */
