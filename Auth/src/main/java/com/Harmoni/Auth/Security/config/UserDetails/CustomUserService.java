package com.Harmoni.Auth.Security.config.UserDetails;

import com.Harmoni.Auth.Security.Exception.UserNotFoundException;
import com.Harmoni.Auth.Security.Auth.UserRepo;
import com.Harmoni.Auth.Security.Auth.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String credential) throws UsernameNotFoundException {
        Users user = userRepo.findByUsername(credential);
        if (user == null) {
            user = userRepo.findByEmail(credential);
        }

        if (user == null) {
            throw new UserNotFoundException("User with credential " + credential + " not found.");
        }

        return User.builder()
                .username(user.getUserName())
                .password(user.getPasswordHash())
                .authorities(Collections.emptyList())
                .build();
    }
}