package com.springsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
// The @EnableWebSecurity is a marker annotation.
// It allows Spring to find and automatically apply the class to the global WebSecurity.

// This is the class where we have all the configuration regarding the Spring Security.
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    // After extending WebSecurityConfigurerAdapter, Right Click -> Generate -> Select Override Methods
    // to see the methods that are available to override.
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

        // We are saying, we want to authorize requests,
        // any request,
        // must be authenticated (i.e., the client must specify the username and password)
        // and
        // the mechanism that we want to enforce the authenticity of the client is by using Http Basic Authentication.
    }
}
