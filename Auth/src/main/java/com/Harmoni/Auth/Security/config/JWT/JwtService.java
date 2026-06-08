package com.Harmoni.Auth.Security.config.JWT;

import com.Harmoni.Auth.Security.Auth.Users;
import com.Harmoni.Auth.Security.Exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    // Token validity: 24 hours
    private static final long TOKEN_VALIDITY = 24 * 60 * 60 * 1000;

    public String generateToken(Users users, String email, String userid) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("userid", userid);

        return Jwts.builder()
                .subject(users.getUsername())
                .claims(claims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public String extractUsername(String jwt) {
        try {
            Claims claims = getClaims(jwt);
            if (claims == null) {
                throw new UnauthorizedException("Unauthorised: Empty claims payload");
            }
            return claims.getSubject();
        } catch (Exception e) {
            throw new UnauthorizedException("Unauthorised");
        }
    }

    public Claims getClaims(String jwt) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
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