package com.Harmoni.Auth.Security.Auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    // 1. Traditional Local Registration Route
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AuthDto.LocalLogin request) {
        String result = authService.registerLocalUser(request);
        return ResponseEntity.ok(result);
    }

    // 2. Traditional Local Login Route
    @PostMapping("/login/local")
    public ResponseEntity<AuthDto.Response> loginLocal(@RequestBody AuthDto.LocalLogin request) {
        AuthDto.Response response = authService.loginLocal(request);
        return ResponseEntity.ok(response);
    }

    // 3. Google OAuth Login Route
    @PostMapping("/login/google")
    public ResponseEntity<AuthDto.Response> loginWithGoogle(@RequestBody AuthDto.GoogleLogin request) {
        AuthDto.Response response = authService.loginWithGoogle(request);
        return ResponseEntity.ok(response);
    }

    // 4. Logout Route
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.substring(7); // "Bearer ".length()
        String result = authService.logout(token);
        return ResponseEntity.ok(result);
    }

    // 5. Change Password Route
    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody AuthDto.ChangePassword request) {
        String result = authService.changePassword(request);
        return ResponseEntity.ok(result);
    }
}
