package com.springsecurity.databaseAuthentication;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.springsecurity.security.UserRoles.ADMIN;
import static com.springsecurity.security.UserRoles.ADMIN_TRAINEE;
import static com.springsecurity.security.UserRoles.STUDENT;

@Repository("FakeRepository")
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> getApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList
                (
                    new ApplicationUser(
                            "Jack",
                            passwordEncoder.encode("password"),
                            STUDENT.getGrantedAuthorities(),
                            true,
                            true,
                            true,
                            true
                    ),
                    new ApplicationUser(
                            "Jill",
                            passwordEncoder.encode("password"),
                            ADMIN.getGrantedAuthorities(),
                            true,
                            true,
                            true,
                            true
                    ),
                    new ApplicationUser(
                            "Tom",
                            passwordEncoder.encode("password"),
                            ADMIN_TRAINEE.getGrantedAuthorities(),
                            true,
                            true,
                            true,
                            true
                    )
                );
        return applicationUsers;
    }
}
