package com.badger.multiplex.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * Endpoint to get the authenticated user's details.
     * Accessible at http://localhost:8080/user/me
     * @param principal The authenticated OAuth2User
     * @return A map of the user's attributes
     */
    @GetMapping("/me")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        return principal.getAttributes();
    }
}
