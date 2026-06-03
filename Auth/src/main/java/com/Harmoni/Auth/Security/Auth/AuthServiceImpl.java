package com.Harmoni.Auth.Security.Auth;

import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import com.Harmoni.Auth.Security.Exception.UserNotFoundException;
import com.Harmoni.Auth.Security.Mail.MailService;
import com.Harmoni.Auth.Security.config.JWT.JwtService;
import com.Harmoni.Auth.Security.config.UserDetails.UserSecurityDetailRepo;
import com.Harmoni.Auth.Security.config.UserDetails.UserSecurityDetails;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Date;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private MailService mailService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserSecurityDetailRepo userSecurityDetailRepo;

    @Value("${google.client.id}")
    private String googleClientId;

    @Override
    public String registerLocalUser(AuthDto.LocalLogin request) {
        Users existingUserByEmail = userRepo.findByEmail(request.getEmail());
        if (existingUserByEmail != null) {
            return "Email is already registered.";
        }

        Users existingUserByUsername = userRepo.findByUsername(request.getUsername());
        if (existingUserByUsername != null) {
            return "Username is already taken.";
        }

        String temporaryPassword = mailService.sendTemporaryPassword(request.getEmail());

        Users newUser = new Users();
        newUser.setUserName(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPasswordHash(passwordEncoder.encode(temporaryPassword));
        newUser.setIsActive(1);
        newUser.setCreatedAt(new java.sql.Timestamp(System.currentTimeMillis()));

        userRepo.save(newUser);

        return "Registration successful. Check your mail for your system-generated password.";
    }

    private void saveOrUpdateTokenDetails(Users user, String token) {
        UserSecurityDetails details = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));
        if (details == null) {
            details = new UserSecurityDetails();
            details.setUserid(user.getUserId());
        }
        details.setToken(token);
        details.setActive(1);
        details.setExpiretime(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000)); // 24 hours
        userSecurityDetailRepo.save(details);
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

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials.");
        }

        String jwtToken = jwtService.generateToken(user, user.getEmail(), String.valueOf(user.getUserId()));
        saveOrUpdateTokenDetails(user, jwtToken);

        return AuthDto.Response.builder()
                .token(jwtToken)
                .email(user.getEmail())
                .userId(String.valueOf(user.getUserId()))
                .build();
    }

    @Override
    public AuthDto.Response loginWithGoogle(AuthDto.GoogleLogin request) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(request.getIdToken());
            
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();
                String email = payload.getEmail();
                String name = (String) payload.get("name");

                Users user = userRepo.findByEmail(email);

                if (user == null) {
                    user = new Users();
                    user.setEmail(email);
                    
                    String baseUsername = name != null ? name.replace(" ", "") : email.split("@")[0];
                    String uniqueUsername = baseUsername;
                    while (userRepo.findByUsername(uniqueUsername) != null) {
                        uniqueUsername = baseUsername + "_" + System.currentTimeMillis() % 10000;
                    }
                    user.setUserName(uniqueUsername);
                    
                    user.setPasswordHash("GOOGLE_AUTH");
                    user.setIsActive(1);
                    user.setCreatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
                    user = userRepo.save(user);
                }

                String jwtToken = jwtService.generateToken(user, user.getEmail(), String.valueOf(user.getUserId()));
                saveOrUpdateTokenDetails(user, jwtToken);

                return AuthDto.Response.builder()
                        .token(jwtToken)
                        .email(user.getEmail())
                        .userId(String.valueOf(user.getUserId()))
                        .build();

            } else {
                throw new UnauthorizedException("Invalid ID token.");
            }
        } catch (Exception e) {
            throw new UnauthorizedException("Google login failed: " + e.getMessage());
        }
    }

    @Override
    public String logout(String token) {
        UserSecurityDetails userSecurityDetails = userSecurityDetailRepo.findByToken(token);
        if (userSecurityDetails != null) {
            userSecurityDetails.setActive(9); // Mark as inactive/logged out
            userSecurityDetailRepo.save(userSecurityDetails);
            return "Logout successful.";
        }
        return "Logout failed: Invalid token.";
    }

    @Override
    public String changePassword(AuthDto.ChangePassword request) {
        Users user = userRepo.findByUsername(request.getUsername());
        if (user == null) {
            throw new UserNotFoundException("User not found.");
        }

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid old password.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepo.save(user);

        // Invalidate all existing tokens for the user
        UserSecurityDetails userSecurityDetails = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));
        if (userSecurityDetails != null) {
            userSecurityDetails.setActive(9);
            userSecurityDetailRepo.save(userSecurityDetails);
        }

        return "Password changed successfully.";
    }
}