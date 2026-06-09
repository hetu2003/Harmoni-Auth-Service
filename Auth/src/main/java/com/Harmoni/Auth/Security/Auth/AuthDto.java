package com.Harmoni.Auth.Security.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDto {
    private AuthDto() {}

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LocalLogin {
        private String username;
        private String password;
        private String email;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GoogleLogin {
        private String idToken;
        private String email;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response {
        private String token;
        private String userId;
        private String email;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ChangePassword {
        private String username;
        private String oldPassword;
        private String newPassword;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ForgotPasswordRequest {
        private String email;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResetPasswordRequest {
        private String token;
        private String newPassword;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EmailOtpSendRequest {
        private String email;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EmailOtpVerifyRequest {
        private String email;
        private String otp;
    }
}
