package com.Harmoni.Auth.Security.config.UserDetails;

import com.Harmoni.Auth.Security.Auth.Users;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsService {
    Users loadUserByUsername(String username) throws UsernameNotFoundException;
}
