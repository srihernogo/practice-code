package com.springsecurity.databaseAuthentication;

import java.util.Optional;

public interface ApplicationUserDAO {
    Optional<ApplicationUser> getApplicationUserByUsername(String username);
}
