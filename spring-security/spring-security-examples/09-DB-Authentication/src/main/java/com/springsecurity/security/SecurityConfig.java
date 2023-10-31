package com.springsecurity.security;

import com.springsecurity.databaseAuthentication.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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

    // When we Autowire, the PasswordEncoder Bean, ApplicationUserService Bean is injected into the Constructor.
    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder,
                          ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    // After extending WebSecurityConfigurerAdapter, Right Click -> Generate -> Select Override Methods
    // to see the methods that are available to override.
    @Override
    protected void configure(HttpSecurity http) throws Exception {
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
//                .httpBasic();     // Commented this to enable Form Based Authentication in below line.

                .formLogin()                            // Enabled Form Based Authentication.
                    .loginPage("/login")             // Custom Login Page.
                        .permitAll()                    // Permitting the Custom Login Page.
                    .defaultSuccessUrl("/courses", true) // Default page to be redirected (Instead of index.html) after login.
                    .usernameParameter("username")  // The Parameter name here and in login.html must be same.
                    .passwordParameter("password")  // The Parameter name here and in login.html must be same.
                .and()
                .rememberMe()
                    // To extend the expiration time of the Cookie SESSIONID.
                    // Default expiration time is 30 Minutes.
                    // When rememberMe() is used, it is extended to 2 weeks!
                    .tokenValiditySeconds(10)   // For longer time, we can use (int) TimeUnit.DAYS.toSeconds(21) for 21 Days.
//                The above line is used to modify the expiration time of Cookies.
                    .key("SomeKey")
                    // This key is used to hash the details (Username, Expiration Time) from the cookies and create md5 hash value.
                    .rememberMeParameter("remember-me") // The Parameter name here and in login.html must be same.
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    // When CSRF is enabled, Logout Request Method must be a POST.
                    // When CSRF is disabled, Logout any Request Method can be used. But the best practice is to use GET.
                    .logoutUrl("/logout")                // Setting the Path for Logout Page. If not set, default is /logout from Spring Security.
                    .clearAuthentication(true)      // Clearing Authentication.
                    .invalidateHttpSession(true)   // Invalidating Http Session.
                    .deleteCookies("JSESSIONID", "remember-me")     // Deleting cookies.
                    .logoutSuccessUrl("/login");                    // Setting the path to be redirected after logout. If not set, default is /login from Spring Security.

        // By default, Spring Security protects the application. Only GET APIs are accessible.
        // To access POST, PUT, DELETE etc., we disable CSRF.
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
