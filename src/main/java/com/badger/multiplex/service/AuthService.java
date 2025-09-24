package com.badger.multiplex.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.badger.multiplex.user.User;
import com.badger.multiplex.user.UserRepository;

import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void saveOrUpdateUser(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            OAuth2User oauthUser = oauthToken.getPrincipal();
            Map<String, Object> attributes = oauthUser.getAttributes();

            String provider = oauthToken.getAuthorizedClientRegistrationId();
            String providerId = getProviderId(provider, attributes);
            String name = (String) attributes.get("name");
            String email = (String) attributes.get("email");

            Optional<User> existingUser = userRepository.findByProviderId(providerId);

            if (existingUser.isPresent()) {
                // Update existing user data
                User user = existingUser.get();
                user.setName(name);
                user.setEmail(email);
                userRepository.save(user);
            } else {
                // Register a new user
                User newUser = new User(providerId, provider, name, email);
                userRepository.save(newUser);
            }
        }
    }

    private String getProviderId(String provider, Map<String, Object> attributes) {
        // The unique ID attribute can be different for each provider
        return switch (provider) {
            case "google" -> (String) attributes.get("sub");
            case "microsoft" -> (String) attributes.get("id"); // Example for Microsoft
            default -> null;
        };
    }
}
