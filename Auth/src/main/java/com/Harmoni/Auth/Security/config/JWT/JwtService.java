package com.Harmoni.Auth.Security.config.JWT;

import com.Harmoni.Auth.Security.Auth.Users;
import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    public static String generateToken(Users userDetails, String email, String userid, String syckey) {
        Map<String, Object> claims = new HashMap<>();
        claims.clear();
        claims.put("email", email);
        claims.put("userid", userid);

        return Jwts.builder()
                .subject(userDetails.getUserName())
                .claims(claims)
                .signWith(Keys.hmacShaKeyFor(syckey.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public String extractUsername(String jwt, String syckey) {
        try {
            Claims claims = getClaims(jwt, syckey);
            if (claims == null) {
                throw new UnauthorizedException("Unauthorised: Empty claims payload");
            }
            return claims.getSubject();
        } catch (Exception e) {
            throw new UnauthorizedException("Unauthorised");
        }
    }

    public Claims getClaims(String jwt, String syckey) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(syckey.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public static String generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}