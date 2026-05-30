package com.Harmoni.Auth.Security.Auth;

public interface AuthService {
    String registerLocalUser(AuthDto.LocalLogin request);

    AuthDto.Response loginLocal(AuthDto.LocalLogin request);

    AuthDto.Response loginWithGoogle(AuthDto.GoogleLogin request);
}
