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
                .antMatchers("/", "index", "/css/*", "/js/*")
                    .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

        // We are saying, we want to authorize requests,
        // Permit all the requests from the URLs that are specified in antMatchers. i.e., Basic Authentication is not required.
            // Added index.html in src/main/resources/static/
            // To access index.html (http://localhost:8080/index.html) authentication is not required as it is added to AntMatchers.
        // Apart from URLs in AntMatchers, authorize any other requests,
        // must be authenticated (i.e., the client must specify the username and password)
        // and
        // the mechanism that we want to enforce the authenticity of the client is by using Http Basic Authentication.
    }
}
