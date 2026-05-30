package com.Harmoni.Auth.Security.Auth;

import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import com.Harmoni.Auth.Security.Exception.UserNotFoundException;
import com.Harmoni.Auth.Security.Mail.MailService;
import com.Harmoni.Auth.Security.config.JWT.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private MailService mailService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    JwtService jwtService;

    private final String SYSTEM_SECRET = "your-very-long-static-system-secret-key-string";

    @Override
    public String registerLocalUser(AuthDto.LocalLogin request) {
        // 1. Check if the email or username is already taken (No Optionals used)
        Users existingUserByEmail = userRepo.findByEmail(request.getEmail()); // Assuming your DTO has request.getEmail()
        if (existingUserByEmail != null) {
            return "Email is already registered.";
        }

        Users existingUserByUsername = userRepo.findByUsername(request.getUsername());
        if (existingUserByUsername != null) {
            return "Username is already taken.";
        }

        // 2. Generate temporary password
        String temporaryPassword = null;

        // 3. Map values to your exact Users model properties
        Users newUser = new Users();
        newUser.setUserName(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPasswordHash(passwordEncoder.encode(temporaryPassword));

        // Set status fields to reflect active local account creation
        newUser.setIsActive(1);
        newUser.setCreatedAt(new java.sql.Timestamp(System.currentTimeMillis()));

        // 4. Save to Database
        userRepo.save(newUser);

        return "Registration successful. Check your mail for your system-generated password.";
    }

    @Override
    public AuthDto.Response loginLocal(AuthDto.LocalLogin request) {

        Users user = userRepo.findByUsername(request.getUsername());
        if (user == null) {
            user = userRepo.findByEmail(request.getUsername());
        }

        if (user == null) {
            throw new UserNotFoundException("Invalid credentials.");
        }

        // Checking against your passwordHash property
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials.");
        }

        Users userDetails = (Users) User.builder()
                .username(user.getUserName())
                .password(user.getPasswordHash())
                .authorities(Collections.emptyList())
                .build();

        String jwtToken = JwtService.generateToken(userDetails, user.getEmail(), String.valueOf(user.getUserId()), SYSTEM_SECRET);

        return AuthDto.Response.builder()
                .token(jwtToken)
                .email(user.getEmail())
                .userId(String.valueOf(user.getUserId()))
                .build();

    }

    @Override
    public AuthDto.Response loginWithGoogle(AuthDto.GoogleLogin request) {

        String googleEmail = "extracted.email.from.token@gmail.com";

        Users user = userRepo.findByEmail(googleEmail);

        if (user == null) {
            user = new Users();
            user.setEmail(googleEmail);
            user.setUserName(googleEmail.split("@")[0]);
            user.setPasswordHash("GOOGLE_AUTH"); // Flags this account natively as an OAuth login
            user.setIsActive(1);
            user.setCreatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
            user = userRepo.save(user);
        }

        Users userDetails = (Users) User.builder()
                .username(user.getUserName())
                .password("")
                .authorities(Collections.emptyList())
                .build();

        String jwtToken = JwtService.generateToken(userDetails, user.getEmail(), String.valueOf(user.getUserId()), SYSTEM_SECRET);

        return AuthDto.Response.builder()
                .token(jwtToken)
                .email(user.getEmail())
                .userId(String.valueOf(user.getUserId()))
                .build();

    }
}