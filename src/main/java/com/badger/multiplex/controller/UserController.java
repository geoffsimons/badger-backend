package com.badger.multiplex.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller to expose the current authenticated user's information.
 * It is designed to work with the stateless JWT authentication flow.
 */
@RestController
public class UserController {

    /**
     * Returns the basic profile information of the currently authenticated user.
     * This method correctly handles the principal type set by the JwtTokenAuthenticationFilter.
     */
    @GetMapping("/user/me")
    public Map<String, Object> user(Authentication authentication) {
        // Ensure authentication object is present (though Spring Security usually guarantees this
        // if the requestMatchers("/user/me").authenticated() chain passed)
        if (authentication == null || authentication.getPrincipal() == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "No authenticated user found.");
            return error;
        }

        Object principal = authentication.getPrincipal();

        // 1. Extract the user identifier (ID/Email)
        String username;
        if (principal instanceof UserDetails userDetails) {
            // This path is taken when the JWT filter successfully authenticated the user.
            username = userDetails.getUsername();
        } else {
            // This is a fallback for other types, e.g., if we were still using session-based OAuth2.
            // For a pure JWT service, this branch might indicate an error or an edge case.
            username = principal.toString();
        }

        // 2. Extract the roles/authorities
        String roles = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(", "));

        // 3. Build the response map using only the data extracted from the token/principal
        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("id", username);
        userDetails.put("roles", roles);
        userDetails.put("authenticated", true);

        return userDetails;
    }
}
