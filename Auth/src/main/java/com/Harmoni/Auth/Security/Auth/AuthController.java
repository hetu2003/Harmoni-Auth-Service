package com.Harmoni.Auth.Security.Auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
