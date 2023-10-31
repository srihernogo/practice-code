package com.springsecurity.databaseAuthentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserService implements UserDetailsService
{
    private final ApplicationUserDAO applicationUserDAO;

    // When we create another class and implement ApplicationUserDAO to fetch users from a real database,
    // we can change the name in @Qualifier.
    @Autowired
    public ApplicationUserService(@Qualifier("FakeRepository") ApplicationUserDAO applicationUserDAO) {
        this.applicationUserDAO = applicationUserDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return applicationUserDAO
                .getApplicationUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("Username %s is not found", username)));
    }
}
