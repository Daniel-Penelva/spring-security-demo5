package com.restapi.springsecuritydemo5.security;

import java.io.IOException;
import java.util.Base64;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.restapi.springsecuritydemo5.user.User;
import com.restapi.springsecuritydemo5.user.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomBasicAuthenticationFilter extends OncePerRequestFilter {
    
    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic ";
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(isBasicAuthentication(request)){                                                           // Verifica se a requisição contém autenticação básica no cabeçalho Authorization usando o método isBasicAuthentication(request).
            String[] credentials = decodeBase64(getHeader(request).replace(BASIC, ""))
                    .split(":");                                                                // Decodifica as credenciais de autenticação básica, remove o prefixo "Basic " do cabeçalho, decodifica a string Base64 resultante e divide as credenciais em um array com o nome de usuário na posição 0 e a senha na posição 1.

            String username = credentials[0];                                                         // Atribui o nome de usuário e a senha extraídos das credenciais decodificadas.
            String password = credentials[1];

            User user = userRepository.findByUsernameFetchRoles(username);

            if(user == null){                                                                         // Se o usuário não for encontrado, define o status da resposta como 401 (UNAUTHORIZED) e escreve uma mensagem indicando que o usuário não existe.
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("User does not exist!");
                return;
            }

            boolean valid = checkPassword(user.getPassword(), password);                              // Verifica se a senha fornecida corresponde à senha armazenada no banco de dados para o usuário encontrado.

            if(!valid){                                                                               // Se a senha não corresponder, define o status da resposta como 401 (UNAUTHORIZED) e escreve uma mensagem indicando que a senha não corresponde.
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Password not match");
                return;
            }

            setAuthentication(user);                                                                   // Se as credenciais forem válidas, autentica o usuário chamando o método setAuthentication(user) para criar um token de autenticação e definir no contexto de segurança.
        }

        filterChain.doFilter(request, response);                                                       // Se a autenticação for bem-sucedida ou se a requisição não contiver autenticação básica, o método doFilter é chamado para encadear a execução dos próximos filtros na cadeia.
    }

    /* Método para criptografar senhas. */
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /* Método é responsável por criar um token de autenticação com base no usuário fornecido e definir esse token no contexto de segurança do Spring Security.*/
    private void setAuthentication(User user) {
        Authentication authentication = createAuthenticationToken(user);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /*Método que cria um token de autenticação com base no usuário encontrado.*/
    private Authentication createAuthenticationToken(User user) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        return new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
    }

    /*Método que verifica se a senha fornecida corresponde à senha armazenada no banco de dados.*/
    private boolean checkPassword(String userPassword, String loginPassword) {
        return passwordEncoder().matches(loginPassword, userPassword);
    }

    /*Método que decodifica uma string codificada em Base64.*/
    private String decodeBase64(String base64) {
        byte[] decodeBytes = Base64.getDecoder().decode(base64);
        return new String(decodeBytes);
    }

    /* Metodo verifica se a requisição contém autenticação básica no cabeçalho Authorization.*/
    private boolean isBasicAuthentication(HttpServletRequest request) {
        String header = getHeader(request);
        return header != null && header.startsWith(BASIC);
    }

    /* Método simplesmente retorna o valor do cabeçalho Authorization da requisição HTTP.*/
    private String getHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION);
    }
}

/* Essa classe é um filtro personalizado que implementa a autenticação básica em uma aplicação web. Ela verifica as credenciais fornecidas pelo 
 * cliente, autentica o usuário e define o token de autenticação no contexto de segurança do Spring Security.
 * */