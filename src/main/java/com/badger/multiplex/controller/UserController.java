package com.badger.multiplex.controller;

import com.badger.multiplex.dto.UserDto;
import com.badger.multiplex.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Controller to expose the current authenticated user's information.
 * It is designed to work with the stateless JWT authentication flow.
 * It fetches detailed user data (name, email) from the UserService/DB
 * using the provider ID found in the JWT.
 */
@RestController
public class UserController {

    private final UserService userService;

    // Inject the UserService
    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Returns the full user profile information, merging details from the JWT (ID, roles)
     * with detailed information from the database (Name, Email).
     */
    @GetMapping("/user/me")
    public Map<String, Object> user(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "No authenticated user found.");
            return error;
        }

        Object principal = authentication.getPrincipal();
        String providerId; // This is the ID (email/provider ID) from the JWT's subject

        // Extract the user identifier (ID/Email) from the JWT principal
        if (principal instanceof UserDetails userDetails) {
            providerId = userDetails.getUsername();
        } else {
            // Fallback for cases where the principal is not a UserDetails object
            providerId = principal.toString();
        }

        // 1. Fetch Name and Email from the database via the UserService
        // The providerId from the JWT is used to look up the User in the DB.
        Optional<UserDto> userDtoOpt = userService.findByProviderId(providerId);

        if (userDtoOpt.isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "User details found in JWT but not in the database for ID: " + providerId);
            return error;
        }

        UserDto userDto = userDtoOpt.get();

        // 2. Extract roles from the Authentication object
        String roles = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(", "));

        // 3. Build the combined response map using fields from the DTO
        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("id", userDto.getId());
        userDetails.put("email", userDto.getEmail());
        userDetails.put("name", userDto.getName());
        userDetails.put("roles", roles);
        userDetails.put("authenticated", true);

        return userDetails;
    }
}
