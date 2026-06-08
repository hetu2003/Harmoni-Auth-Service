package com.Harmoni.Auth.Security.Auth;

public interface AuthService {
    String registerLocalUser(UserRegisterDto registerDto, String profilePath);

    AuthDto.Response loginLocal(AuthDto.LocalLogin request);

    AuthDto.Response loginWithGoogle(AuthDto.GoogleLogin request);

    String logout(String token);

    String changePassword(AuthDto.ChangePassword request);

    String processForgotPassword(AuthDto.ForgotPasswordRequest request);

    String processResetPassword(AuthDto.ResetPasswordRequest request);
}
