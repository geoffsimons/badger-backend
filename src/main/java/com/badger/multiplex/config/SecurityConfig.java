package com.badger.multiplex.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

    @Autowired
    public SecurityConfig(
            OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
            JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter) {
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.jwtTokenAuthenticationFilter = jwtTokenAuthenticationFilter;
    }

    // **Change the order of this chain to a high-priority (low-number) order**
    @Bean
    @Order(1) // Run this chain first. It contains the OAuth2 login logic.
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ... (other config)
            // **IMPORTANT:** Exclude the actuator path from this chain.
            // This is only necessary if you had a different matcher, but let's be explicit
            // to avoid issues if the Actuator chain is ever removed.
            .authorizeHttpRequests(auth -> auth
                // This line is now CRITICAL to allow the OAuth2 endpoints to pass through.
                // Spring Security 6+ will register the internal OAuth2 endpoints
                // (/oauth2/authorization/*, /login/oauth2/code/*) to the chain that has .oauth2Login().
                // .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/user/me").authenticated()
                .anyRequest().permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2LoginSuccessHandler)
            )
            .addFilterBefore(jwtTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // **Change the order of this chain to a lower-priority (higher-number) order**
    @Bean
    @Order(2) // Run this chain second, only for actuator paths.
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {

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
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://app.geoffsimons.com"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
