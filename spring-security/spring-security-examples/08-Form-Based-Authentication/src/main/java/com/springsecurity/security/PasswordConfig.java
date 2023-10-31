package com.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Bean   // Do a Ctrl+Click on PasswordEncoder to see available methods.
    public PasswordEncoder passwordEncoder()
    {
        // BCryptPasswordEncoder is the most popular Password Encoders.
        return new BCryptPasswordEncoder(10);   // 10 is the Password Strength.
    }
}
