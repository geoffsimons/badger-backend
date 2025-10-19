package com.badger.multiplex.config;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order; // Needed for ordering

@Configuration
@Profile("local") // Only active when 'local' profile is set
public class LocalSecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(LocalSecurityConfig.class);

    private static final List<String> LOGGED_ROUTES = List.of("/login", "/oauth2", "/user");

    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    @Autowired
    public LocalSecurityConfig(
            OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
            JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter,
            CorsConfigurationSource corsConfigurationSource) {
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.jwtTokenAuthenticationFilter = jwtTokenAuthenticationFilter;
        this.corsConfigurationSource = corsConfigurationSource;
    }

    private boolean shouldLog(HttpServletRequest request) {
        String path = request.getRequestURI();
        return LOGGED_ROUTES.stream().anyMatch(path::contains);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain localSecurityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore((request, response, chain) -> {
            if (shouldLog((HttpServletRequest) request)) {
                HttpServletRequest req = (HttpServletRequest) request;
                logger.info("Request matched LOCAL Chain (Order 2) for URI: {} query: {}",
                    ((HttpServletRequest) req).getRequestURI(),
                    ((HttpServletRequest) req).getQueryString());
                logger.info("X-Forwarded-Proto: {}", req.getHeader("X-Forwarded-Proto"));
                logger.info("X-Forwarded-Host: {}", req.getHeader("X-Forwarded-Host"));
            }
            chain.doFilter(request, response);
        }, WebAsyncManagerIntegrationFilter.class);

        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/user/me").authenticated()
                .anyRequest().permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2LoginSuccessHandler)
            )
            .addFilterBefore(jwtTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Note: You must also ensure that corsConfigurationSource() is accessible or defined here
    // if the main config's bean isn't picked up correctly due to profile separation.
    // For simplicity, I'm assuming the main config's CorsConfigurationSource bean is still picked up.
    // If not, you'd define it here again, or move the CorsConfigurationSource bean
    // to a third, un-profiled @Configuration class.
}
