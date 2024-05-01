package com.restapi.springsecuritydemo5.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User create(User user) {

        User existUser = userRepository.findByUsername(user.getUsername());

        if (existUser != null) {
            throw new Error("User already exists!");
        }

        user.setPassword(passwordEncoder().encode(user.getPassword()));
        return userRepository.save(user);
    }


    // Criptografar a senha
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
