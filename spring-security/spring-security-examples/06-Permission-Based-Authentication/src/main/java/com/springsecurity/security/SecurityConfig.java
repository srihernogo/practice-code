package com.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.springsecurity.security.UserRoles.ADMIN;
import static com.springsecurity.security.UserRoles.ADMIN_TRAINEE;
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
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    private final PasswordEncoder passwordEncoder;

    // When we Autowire, the PasswordEncoder Bean is injected into the Constructor.
    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // After extending WebSecurityConfigurerAdapter, Right Click -> Generate -> Select Override Methods
    // to see the methods that are available to override.
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http
                .csrf().disable()
                .authorizeRequests()

                .antMatchers("/", "index", "/css/*", "/js/*")
                    .permitAll()

                .antMatchers("/api/**")
                    .hasRole(STUDENT.name())  // "/api/**" works. "/api/*" doesn't work.

//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
//                The above 4 antMatchers are Permission Based Authentication using AntMatchers.
//                Commented the above antMatchers as we have used Permission Based Authentication
//                using @PreAuthorize Annotation in StudentManagementController.

                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

        // By default, Spring Security protects the application. Only GET APIs are accessible.
        // To access POST, PUT, DELETE etc, we disable CSRF.
        // We are saying, we want to authorize requests,

        // Permit all the requests from the URLs that are specified in antMatchers. i.e., Basic Authentication is not required.
            // Added index.html in src/main/resources/static/
            // To access index.html (http://localhost:8080/index.html) authentication is not required as it is added to AntMatchers.

        // To access APIs whose URL starts with /api/**, the user must have STUDENT Role.

        // To access APIs whose URL starts with /management/api/** and Http Method is DELETE, the user must have COURSE_WRITE Permission.
        // To access APIs whose URL starts with /management/api/** and Http Method is POST, the user must have COURSE_WRITE Permission.
        // To access APIs whose URL starts with /management/api/** and Http Method is PUT, the user must have COURSE_WRITE Permission.
        // To access APIs whose URL starts with /management/api/** and Http Method is GET, the user can have either ADMIN or ADMIN_TRAINEE Role.

        // Apart from URLs in AntMatchers, authorize any other requests,
        // must be authenticated (i.e., the client must specify the username and password)
        // and
        // the mechanism that we want to enforce the authenticity of the client is by using Http Basic Authentication.
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails jack = User.builder()
                .username("Jack")
//                .password("password")
                // We cannot use .password("password").
                // When we try to hit the API, the password is encoded when it comes to the application.
                // We also must encode the password specified above.
                // So, defined an encoder in the PasswordConfig.
                // Hence .password("password") has to be written as below:
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name())
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                // This is the concept of Permission Based Authentication.
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        // Defining Admin User
        UserDetails jill = User.builder()
                .username("Jill")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name())
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                // This is the concept of Permission Based Authentication.
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN_TRAINEE.name())
                // Commented the above line to specify the Roles along with the Authorities to the Users like below.
                // This is the concept of Permission Based Authentication.
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        // This method is used to retrieve User Details from a Database.
        // For now, I have configured Users here.

        // Do a Ctrl+Click on UserDetailsService and inside that check which classes
        // implements this Interface. There are around 5-6 options such as InMemoryUserDetailsManager etc.
        // I have used InMemoryUserDetailsManager.

        return new InMemoryUserDetailsManager(jack, jill, tom);
    }
}
