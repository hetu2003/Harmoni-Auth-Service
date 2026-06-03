package com.Harmoni.Auth.Security.config.JWT;

import com.Harmoni.Auth.Security.Auth.UserRepo;
import com.Harmoni.Auth.Security.Auth.Users;
import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import com.Harmoni.Auth.Security.config.UserDetails.CustomUserService;
import com.Harmoni.Auth.Security.config.UserDetails.UserSecurityDetailRepo;
import com.Harmoni.Auth.Security.config.UserDetails.UserSecurityDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Configuration
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private CustomUserService customUserService;

    @Autowired
    private UserSecurityDetailRepo userSecurityDetailRepo;

    @Autowired
    private UserRepo userRepo;

    @Scheduled(cron = "0 */5 * ? * *")
    public void deactivateExpiredTokens() {
        try {
            List<UserSecurityDetails> userSecurityDetailsList = userSecurityDetailRepo.findAll();
            Instant now = Instant.now();
            for (UserSecurityDetails userSecurityDetail : userSecurityDetailsList) {
                if (userSecurityDetail.getExpiretime().before(Date.from(now))) {
                    userSecurityDetail.setActive(9);
                    userSecurityDetailRepo.save(userSecurityDetail);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException  {

        String authHeader = request.getHeader("Authorization");
        String seckey = request.getHeader("seckey");

        // 1. If there's no bearer token, skip authorization filter checks and move to the next filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);
        String username = jwtService.extractUsername(jwt);

        // 2. Fetch User directly (No Optionals)
        Users user = userRepo.findByEmail(username);
        if (user == null) {
            user = userRepo.findByUsername(username);
        }

        if (user == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Look up token lifecycle details
        UserSecurityDetails userSecurityDetail = userSecurityDetailRepo.findbyUserId(String.valueOf(user.getUserId()));

        if (userSecurityDetail == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 4. Validate context and database token state match
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null
                && jwt.equals(userSecurityDetail.getToken())) {

            Users userDetails = (Users) customUserService.loadUserByUsername(username);

            if (userDetails != null && userSecurityDetail.getExpiretime().after(Date.from(Instant.now()))) {
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, java.util.Collections.emptyList());

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } else {
                userSecurityDetail.setActive(9);
                userSecurityDetailRepo.save(userSecurityDetail);
                throw new UnauthorizedException("Token Expired.");
            }
        }
        filterChain.doFilter(request, response);
    }
}