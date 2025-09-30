package com.badger.multiplex.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Base64;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class for generating and validating JSON Web Tokens (JWTs).
 */
@Component
public class JwtTokenProvider {

    private final long jwtExpirationInMs;
    private final Key signingKey;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.ttl}") long jwtExpirationInMs) {

        this.jwtExpirationInMs = jwtExpirationInMs;

        try {
            byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Failed to decode JWT secret. Please ensure 'jwt.secret' in application.properties " +
                "is a valid, Base64-encoded string.", e);
        }
    }

    /**
     * Generates a JWT token for the authenticated user.
     * @param authentication The Spring Security Authentication object.
     * @return The minted JWT as a String.
     */
    public String generateToken(Authentication authentication) {
        String userId = authentication.getName();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .subject(userId)
                .claim("roles", authorities)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Extracts user authentication information from the JWT.
     * @param token The JWT.
     * @return An Authentication object populated with token claims.
     */
    public Authentication getAuthentication(String token) {
        // Parse the token and extract claims
        Claims claims = Jwts.parser()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // Extract authorities (roles) from the custom "roles" claim
        String rolesString = (String) claims.get("roles");
        List<SimpleGrantedAuthority> authorities = Arrays.stream(rolesString.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Create a UserDetails object (stateless, based only on token info)
        User principal = new User(claims.getSubject(), "", authorities);

        // Return a fully authenticated Authentication token
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /**
     * Validates the JWT.
     * @param authToken The JWT string.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(signingKey).build().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            System.out.println("Invalid JWT signature: " + ex.getMessage());
        } catch (MalformedJwtException ex) {
            System.out.println("Invalid JWT token: " + ex.getMessage());
        } catch (ExpiredJwtException ex) {
            System.out.println("Expired JWT token: " + ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            System.out.println("Unsupported JWT token: " + ex.getMessage());
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty: " + ex.getMessage());
        }
        return false;
    }
}
