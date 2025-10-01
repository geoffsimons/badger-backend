package com.badger.multiplex.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Utility class for generating and validating JSON Web Tokens (JWTs).
 * Uses properties injected from application.properties for secret and TTL.
 */
@Component
public class JwtTokenProvider {

    private final SecretKey signingKey;
    private final long tokenValidityInMilliseconds;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.ttl}") long tokenValidityInMilliseconds) {
        // Generates an HMAC SHA key from the Base64-encoded secret for use with HS512.
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds;
    }

    /**
     * Creates a JWT token for the given authentication object.
     */
    public String createToken(Authentication authentication) {
        String userId = authentication.getName(); // The subject of the token (e.g., email or provider ID)
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + tokenValidityInMilliseconds);

        return Jwts.builder()
                .subject(userId) // The ID/name of the authenticated user
                .claim("roles", authorities) // Custom claim for user roles
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(signingKey) // Uses the HS512 algorithm
                .compact();
    }

    /**
     * Extracts authentication information from the JWT.
     */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey) // Sets the key for verification
                .build()
                .parseSignedClaims(token) // Returns Jws<Claims>
                .getPayload(); // Retrieves the Claims object (payload)

        // Extract user roles (authorities)
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("roles").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // Create a UserDetails object with the token's subject (ID) and authorities
        User principal = new User(claims.getSubject(), "", authorities);

        // Return a fully authenticated token
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /**
     * Validates the JWT token's signature and expiration date.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(signingKey) // Sets the key for verification
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException e) {
            // Catch all specific JWT exceptions for clear logging
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (java.lang.IllegalArgumentException e) {
            // Catch java.lang.IllegalArgumentException for null/empty token string
            System.err.println("Token argument error: " + e.getMessage());
        }
        return false;
    }
}
