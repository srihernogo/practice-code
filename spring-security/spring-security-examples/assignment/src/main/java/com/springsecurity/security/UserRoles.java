package com.springsecurity.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Set;
import java.util.stream.Collectors;
import static com.springsecurity.security.UserPermissions.*;

@AllArgsConstructor
@Getter
public enum UserRoles
{
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));
    
    private final Set<UserPermissions> permissions;

    // We write the below method to specify the Authorities to the Roles.
    // In the SecurityConfig, instead of .roles(ADMIN.name()) we can use .authorities(ADMIN.getGrantedAuthorities())
    // By doing this, along with the Roles, the Permissions are also defined to the User.
    public Set<SimpleGrantedAuthority> getGrantedAuthorities()
    {
        Set<SimpleGrantedAuthority> permissions = this.getPermissions()
                                                .stream()
                                                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                                                .collect(Collectors.toSet());

        // In the above line, we add the permissions to the Set.
        // In the below line, we add the Role to the Set.
        // So, for example, the Set for ADMINTRAINEE looks like {"ROLE_ADMINTRAINEE", "course":"read", "student":"read"}

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
