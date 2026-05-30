package com.Harmoni.Auth.Security.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDto {
    // Private constructor prevents instantiation of the wrapper container
    private AuthDto() {
    }

    // 1. Traditional Login Request
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LocalLogin {
        private String username;
        private String password;
        private String email;
    }

    // 2. Google OAuth Request
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GoogleLogin {
        private String idToken;
    }

    // 3. Combined Response
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response {
        private String token;
        private String userId;
        private String email;
    }
}
