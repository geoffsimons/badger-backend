package com.badger.multiplex.config;

import com.badger.multiplex.jwt.JwtTokenProvider;
import com.badger.multiplex.service.AuthService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Custom success handler for OAuth2 login.
 * Mints a JWT upon successful authentication and redirects the user to the
 * specified frontend URI with the JWT appended as a query parameter.
 */
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final JwtTokenProvider tokenProvider;
    private final AuthService authService;

    // Injects the success redirect URI defined in application.properties
    @Value("${app.oauth2.redirect-uri-success}")
    private String redirectUriSuccess;

    public OAuth2LoginSuccessHandler(JwtTokenProvider tokenProvider, AuthService authService) {
        this.tokenProvider = tokenProvider;
        this.authService = authService;
    }

    /**
     * Called when a user has been successfully authenticated via OAuth2.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        logger.info("onAuthenticationSuccess, URI: {}", request.getRequestURI());

        // Store the user in the db, or update the record with any name changes.
        authService.saveOrUpdateUser(authentication);

        // 1. Generate the JWT for the authenticated user
        String jwt = tokenProvider.createToken(authentication);

        // 2. Build the final redirect URI with the JWT as a query parameter
        // The frontend will read this 'token' param.
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUriSuccess)
                .queryParam("token", jwt)
                .build().toUriString();

        // 3. Redirect the user to the frontend with the JWT
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
