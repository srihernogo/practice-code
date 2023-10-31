package com.springsecurity.security;

import com.springsecurity.databaseAuthentication.ApplicationUserService;
import com.springsecurity.jwt.JwtConfig;
import com.springsecurity.jwt.JwtTokenVerifier;
import com.springsecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.springsecurity.security.UserRoles.STUDENT;

@Configuration
@EnableWebSecurity
// The @EnableWebSecurity is a marker annotation.
// It allows Spring to find and automatically apply the class to the global WebSecurity.

@EnableGlobalMethodSecurity(prePostEnabled = true)
// prePostEnabled is false by default.
// @EnableGlobalMethodSecurity Annotation is used to tell the Configuration that
// we want to use Annotations for Role and Permission Based Authentication.

// This is the class where we have all the configuration regarding the Spring Security.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    // When we Autowire, the PasswordEncoder Bean, ApplicationUserService Bean, JwtConfig Bean & SecretKey
    // is injected into the Constructor.
    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder,
                          ApplicationUserService applicationUserService,
                          JwtConfig jwtConfig,
                          SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                As JWT is Stateless, we define Session Creation Policy as STATELESS in the above line.
//                Now the Session won't be stored in a Database.

                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
//                Added a Filter.
//                We have access to authenticationManager() method from WebSecurityConfigurerAdapter Class as we have extended it.

                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
//                Added another Filter.
//                This Filter will be executed after the JwtUsernameAndPasswordAuthenticationFilter.

                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())  // "/api/**" works. "/api/*" doesn't work.
                .anyRequest()
                .authenticated();
    }

    @Override   // This method is to set the AuthenticationProvider.
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean       // Created DaoAuthenticationProvider and set the Password Encoder and Custom UserDetailsService.
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
