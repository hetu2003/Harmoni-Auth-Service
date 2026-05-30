package com.Harmoni.Auth.Security.config.Handlers;

import com.Harmoni.Auth.Security.Auth.AuthDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class SuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        User principal = (User) authentication.getPrincipal();

        // 1. Generate token details (Replace with your actual service invocation)
        // String token = JWTService.generateToken(principal, ...);

        AuthDto.Response authResponse = AuthDto.Response.builder()
                .token("generated-jwt-token-here")
                .email(principal.getUsername())
                .userId("extracted-user-id")
                .build();

        // 2. Write JSON directly to the response body for the frontend
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);

        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
    }
}
