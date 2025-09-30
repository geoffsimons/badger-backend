package com.badger.multiplex.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Utility class for generating JSON Web Tokens (JWTs).
 *
 * NOTE: For production use, install a library like 'jjwt' and replace the
 * placeholder return with secure token generation logic.
 */
@Component
public class JwtTokenProvider {

    private final long jwtExpirationInMs;
    private final Key signingKey; // Secure Key for signing the JWT

    // Constructor injection for loading properties and initializing the key
    public JwtTokenProvider(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.ttl}") long jwtExpirationInMs) {

        this.jwtExpirationInMs = jwtExpirationInMs;

        // Ensure the secret is securely decoded into a Key object for signing
        // It is assumed the value in application.properties is base64-encoded.
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generates a JWT token for the authenticated user.
     * @param authentication The Spring Security Authentication object.
     * @return The minted JWT as a String.
     */
    public String generateToken(Authentication authentication) {
        // Extract the user identifier (e.g., the OAuth2 user's email/ID)
        String userId = authentication.getName();

        // Extract roles/authorities and format them as a comma-separated string claim
        String authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        // Actual JWT creation using JJWT library
        return Jwts.builder()
                .subject(userId) // The ID/name of the authenticated user
                .claim("roles", authorities) // Custom claim for user roles
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(signingKey)
                .compact();
    }
  }
