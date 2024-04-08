package com.miniproject.spring.jwt.service;

import com.miniproject.spring.jwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private Claims extractClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isValid(String token, User user) {
       String username = extractClaims(token).getSubject();
       return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extrackExpiration(token).before(new Date());
    }

    private Date extrackExpiration(String token) {
        return extrackClaim(token, Claims::getExpiration);
    }

    private final String SECRET_KEY = "2d80f13524d11792ecb1b41f595f97bad71cdd4d9621fe0e8db2c64ce47e8a18";
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }
    public <T> T extrackClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractClaims(token);
        return resolver.apply(claims);
    }
    public String generateToken(User user) {
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSigninKey())
                .compact();
        return token;
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
