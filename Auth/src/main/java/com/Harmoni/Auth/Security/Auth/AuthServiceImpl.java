package com.Harmoni.Auth.Security.Auth;

import com.Harmoni.Auth.Security.CouchDb.EmailLoginAuditRepository;
import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import com.Harmoni.Auth.Security.Exception.UserNotFoundException;
import com.Harmoni.Auth.Security.Mail.MailService;
import com.Harmoni.Auth.Security.Otp.OtpService;
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

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

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

    @Autowired
    private OtpService otpService;

    @Autowired
    private EmailLoginAuditRepository auditRepository;

    @Value("${google.client.id}")
    private String googleClientId;
    
    @Override
    public String registerLocalUser(UserRegisterDto request, String uploadedProfilePath) {
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
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPasswordHash(passwordEncoder.encode(temporaryPassword));

        String lastName = request.getLastName() != null ? request.getLastName() : "";
        String fullName = (request.getFirstName() + " " + lastName).trim();
        newUser.setName(fullName);

        newUser.setRoleId(request.getRoleId());
        newUser.setContactNumber(request.getContactNumber());
        newUser.setStreetAddress(request.getStreetAddress());
        newUser.setStateId(request.getStateId());
        newUser.setCityId(request.getCityId());
        newUser.setCompanyDescription(request.getSpecialCategory());
        newUser.setProfilePath(uploadedProfilePath);

        newUser.setIsActive(1);
        Timestamp now = new Timestamp(System.currentTimeMillis());
        newUser.setCreatedAt(now);
        newUser.setModifiedOn(now);
        newUser.setCreatedBy(0);
        newUser.setModifiedBy(0);

        userRepo.save(newUser);

        return "Registration successful. Check your mail for your system-generated password.";
    }

    private void saveOrUpdateTokenDetails(Users user, String token) {
        UserSecurityDetails details = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));
        if (details == null) {
            details = new UserSecurityDetails();
            details.setUserid(String.valueOf(user.getUserId()));
        }
        details.setToken(token);
        details.setActive(1);
        details.setExpiretime(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000));
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
                    user.setUsername(uniqueUsername);
                    
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
            userSecurityDetails.setActive(9);
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

        UserSecurityDetails userSecurityDetails = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));
        if (userSecurityDetails != null) {
            userSecurityDetails.setActive(9);
            userSecurityDetailRepo.save(userSecurityDetails);
        }

        return "Password changed successfully.";
    }

    @Override
    public String processForgotPassword(AuthDto.ForgotPasswordRequest request) {
        Users user = userRepo.findByEmail(request.getEmail());
        if (user == null) {
            // Return success even if user not found to prevent email enumeration attacks
            return "If that email exists, a password reset link has been sent.";
        }

        // Generate a unique token
        String resetToken = UUID.randomUUID().toString();
        user.setResetPasswordToken(resetToken);
        userRepo.save(user);

        // Construct the reset link (pointing to the Master frontend)
        // In a real app, this base URL should come from properties
        String resetLink = "http://localhost:8082/harmoni/reset-password?token=" + resetToken;

        mailService.sendPasswordResetEmail(user.getEmail(), resetLink);

        return "If that email exists, a password reset link has been sent.";
    }

    @Override
    public String processResetPassword(AuthDto.ResetPasswordRequest request) {
        Users user = userRepo.findByResetPasswordToken(request.getToken());
        if (user == null) {
            return "Invalid or expired reset token.";
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        // Invalidate the token so it can't be used again
        user.setResetPasswordToken(null);
        userRepo.save(user);

        // Invalidate active sessions
        UserSecurityDetails userSecurityDetails = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));
        if (userSecurityDetails != null) {
            userSecurityDetails.setActive(9);
            userSecurityDetailRepo.save(userSecurityDetails);
        }

        return "Password reset successfully. You can now login.";
    }

    @Override
    public String updateProfile(Long userId, UpdateProfileRequest request, String profilePath) {
        Users user = userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found."));

        if (request.getName() != null && !request.getName().isBlank()) {
            user.setName(request.getName());
        }
        if (request.getContactNumber() != null && !request.getContactNumber().isBlank()) {
            user.setContactNumber(request.getContactNumber());
        }
        if (request.getStreetAddress() != null && !request.getStreetAddress().isBlank()) {
            user.setStreetAddress(request.getStreetAddress());
        }
        if (request.getCityId() != null) {
            user.setCityId(request.getCityId());
        }
        if (request.getStateId() != null) {
            user.setStateId(request.getStateId());
        }
        if (request.getCompanyDescription() != null) {
            user.setCompanyDescription(request.getCompanyDescription());
        }
        if (profilePath != null && !profilePath.isBlank()) {
            user.setProfilePath(profilePath);
        }

        user.setModifiedOn(new Timestamp(System.currentTimeMillis()));
        userRepo.save(user);
        return "Profile updated successfully.";
    }

    @Override
    public String sendEmailOtp(AuthDto.EmailOtpSendRequest request) {
        Users user = userRepo.findByEmail(request.getEmail());
        if (user == null) {
            // Return success to prevent email enumeration
            return "If that email is registered, an OTP has been sent.";
        }
        String otp = otpService.generateAndStoreOtp(request.getEmail());
        mailService.sendOtpEmail(request.getEmail(), otp);
        auditRepository.logEvent(request.getEmail(), "EMAIL_OTP_SEND", "SUCCESS",
                String.valueOf(user.getUserId()), "OTP sent");
        return "OTP sent to your email. It expires in 5 minutes.";
    }

    @Override
    public AuthDto.Response verifyEmailOtp(AuthDto.EmailOtpVerifyRequest request) {
        Users user = userRepo.findByEmail(request.getEmail());
        if (user == null) {
            auditRepository.logEvent(request.getEmail(), "EMAIL_OTP_VERIFY_FAIL", "FAILED",
                    null, "User not found");
            throw new UserNotFoundException("Invalid credentials.");
        }

        boolean valid = otpService.verifyOtp(request.getEmail(), request.getOtp());
        if (!valid) {
            auditRepository.logEvent(request.getEmail(), "EMAIL_OTP_VERIFY_FAIL", "FAILED",
                    String.valueOf(user.getUserId()), "Invalid or expired OTP");
            throw new UnauthorizedException("Invalid or expired OTP.");
        }

        String jwtToken = jwtService.generateToken(user, user.getEmail(), String.valueOf(user.getUserId()));
        saveOrUpdateTokenDetails(user, jwtToken);

        auditRepository.logEvent(request.getEmail(), "EMAIL_OTP_VERIFY_SUCCESS", "SUCCESS",
                String.valueOf(user.getUserId()), "Login successful");

        return AuthDto.Response.builder()
                .token(jwtToken)
                .email(user.getEmail())
                .userId(String.valueOf(user.getUserId()))
                .build();
    }
}
