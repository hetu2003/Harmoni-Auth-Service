package com.Harmoni.Auth.Security.Auth;

import com.Harmoni.Auth.Security.Mail.MailService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.Harmoni.Auth.Security.config.JWT.JwtService;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private MailService mailService;

    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> registerUser(
            @ModelAttribute @Valid UserRegisterDto registerDto,
            @RequestParam(value = "profilePhoto", required = false) MultipartFile file) {

        String profilePath = null;
        if (file != null && !file.isEmpty()) {
            try {
                profilePath = "/uploads/profiles/" + file.getOriginalFilename();
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload profile photo.");
            }
        }
        String responseMessage = authService.registerLocalUser(registerDto, profilePath);
        return responseMessage.contains("successful") ? ResponseEntity.ok(responseMessage) : ResponseEntity.badRequest().body(responseMessage);
    }

    @PostMapping("/login/local")
    public ResponseEntity<AuthDto.Response> loginLocal(@RequestBody AuthDto.LocalLogin request) {
        return ResponseEntity.ok(authService.loginLocal(request));
    }

    @PostMapping("/login/google")
    public ResponseEntity<AuthDto.Response> loginWithGoogle(@RequestBody AuthDto.GoogleLogin request) {
        return ResponseEntity.ok(authService.loginWithGoogle(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader) {
        return ResponseEntity.ok(authService.logout(authorizationHeader.substring(7)));
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody AuthDto.ChangePassword request) {
        return ResponseEntity.ok(authService.changePassword(request));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody AuthDto.ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.processForgotPassword(request));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody AuthDto.ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.processResetPassword(request));
    }

    @PostMapping(value = "/update-profile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> updateProfile(
            @RequestHeader("Authorization") String authorizationHeader,
            @ModelAttribute UpdateProfileRequest request,
            @RequestParam(value = "profilePhoto", required = false) MultipartFile file) {
        
        String token = authorizationHeader.substring(7);
        Claims claims = jwtService.getClaims(token);
        Long userId = Long.parseLong(claims.get("userid", String.class));

        String profilePath = null;
        if (file != null && !file.isEmpty()) {
            try {
                profilePath = "/uploads/profiles/" + file.getOriginalFilename();
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload profile photo.");
            }
        }

        String result = authService.updateProfile(userId, request, profilePath);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/login/email/send-otp")
    public ResponseEntity<String> sendEmailOtp(@RequestBody AuthDto.EmailOtpSendRequest request) {
        return ResponseEntity.ok(authService.sendEmailOtp(request));
    }

    @PostMapping("/login/email/verify-otp")
    public ResponseEntity<AuthDto.Response> verifyEmailOtp(@RequestBody AuthDto.EmailOtpVerifyRequest request) {
        return ResponseEntity.ok(authService.verifyEmailOtp(request));
    }

    @PostMapping("/send-email")
    public ResponseEntity<Void> sendEmail(@RequestBody EmailRequest emailRequest) {
        mailService.sendGenericEmail(emailRequest);
        return ResponseEntity.ok().build();
    }
}
