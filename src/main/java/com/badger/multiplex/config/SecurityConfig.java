package com.badger.multiplex.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private static final List<String> LOGGED_ROUTES = List.of("/login", "/oauth2", "/user");

    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

    @Autowired
    public SecurityConfig(
            OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
            JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter) {
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.jwtTokenAuthenticationFilter = jwtTokenAuthenticationFilter;
    }

    // Helper method to check if the request should be logged
    private boolean shouldLog(HttpServletRequest request) {
        String path = request.getRequestURI();
        return LOGGED_ROUTES.stream().anyMatch(path::contains);
    }

    // **Change the order of this chain to a high-priority (low-number) order**
    @Bean
    @Order(2) // Must be last
    @ConditionalOnMissingBean(name = "localSecurityFilterChain") // Only create if local is not defined.
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore((request, response, chain) -> {
            if (shouldLog((HttpServletRequest) request)) {
                HttpServletRequest req = (HttpServletRequest) request;
                logger.debug("Request matched APPLICATION Chain (Order 2) for URI: {} query: {}",
                    ((HttpServletRequest) req).getRequestURI(),
                    ((HttpServletRequest) req).getQueryString());
                logger.debug("X-Forwarded-Proto: {}", req.getHeader("X-Forwarded-Proto"));
                logger.debug("X-Forwarded-Host: {}", req.getHeader("X-Forwarded-Host"));
            }
            chain.doFilter(request, response);
        }, WebAsyncManagerIntegrationFilter.class);

        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for a stateless REST API
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
            .securityMatcher("/**")
            // This helps resolve the way the AWS LB works, but we do not want it for the actuator below.
            .requiresChannel(channel -> channel.anyRequest().requiresSecure())
            // **IMPORTANT:** Exclude the actuator path from this chain.
            // This is only necessary if you had a different matcher, but let's be explicit
            // to avoid issues if the Actuator chain is ever removed.
            .authorizeHttpRequests(auth -> auth
                // This line is now CRITICAL to allow the OAuth2 endpoints to pass through.
                // Spring Security 6+ will register the internal OAuth2 endpoints
                // (/oauth2/authorization/*, /login/oauth2/code/*) to the chain that has .oauth2Login().
                .requestMatchers("/login", "/error", "/oauth2").permitAll()
                .requestMatchers("/user/me").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2LoginSuccessHandler)
            )
            .addFilterBefore(jwtTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // **Change the order of this chain to a lower-priority (higher-number) order**
    @Bean
    @Order(1) // Must be first, because our matcher is more specific.
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        // TODO: We can very likely remove/modify this log message because it never fires, because this chain filters to only "/actuator/**"
        http.addFilterBefore((request, response, chain) -> {
            if (shouldLog((HttpServletRequest) request)) {
                logger.debug("Request matched ACTUATOR Chain (Order 1) for URI: {} query: {}",
                    ((HttpServletRequest) request).getRequestURI(),
                    ((HttpServletRequest) request).getQueryString());
            }
            chain.doFilter(request, response);
        }, WebAsyncManagerIntegrationFilter.class);

        // 1. Configure Actuator Endpoints
        http
            .securityMatcher("/actuator/**") // Only apply this chain to /actuator/**
            .csrf(csrf -> csrf.disable())

            // 2. Authorize ALL requests on the Actuator path
            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            );

        return http.build();
    }

    // CORS Configuration (Essential for frontend on 3000)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "https://app.geoffsimons.com"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
