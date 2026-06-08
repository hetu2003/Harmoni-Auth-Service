package com.Harmoni.Auth.Security.Auth;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> registerUser(
            @ModelAttribute @Valid UserRegisterDto registerDto,
            @RequestParam("profilePhoto") MultipartFile file) {

        String profilePath = null;

        if (file != null && !file.isEmpty()) {
            try {
                profilePath = "/uploads/profiles/" + file.getOriginalFilename();
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to upload profile photo.");
            }
        }

        String responseMessage = authService.registerLocalUser(registerDto, profilePath);

        if (responseMessage != null && responseMessage.contains("successful")) {
            return ResponseEntity.ok(responseMessage);
        } else {
            return ResponseEntity.badRequest().body(responseMessage);
        }
    }

    @PostMapping("/login/local")
    public ResponseEntity<AuthDto.Response> loginLocal(@RequestBody AuthDto.LocalLogin request) {
        AuthDto.Response response = authService.loginLocal(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login/google")
    public ResponseEntity<AuthDto.Response> loginWithGoogle(@RequestBody AuthDto.GoogleLogin request) {
        AuthDto.Response response = authService.loginWithGoogle(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.substring(7);
        String result = authService.logout(token);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody AuthDto.ChangePassword request) {
        String result = authService.changePassword(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody AuthDto.ForgotPasswordRequest request) {
        String result = authService.processForgotPassword(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody AuthDto.ResetPasswordRequest request) {
        String result = authService.processResetPassword(request);
        return ResponseEntity.ok(result);
    }
}
