package com.badger.multiplex.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order; // Needed for ordering

@Configuration
@Profile("local") // Only active when 'local' profile is set
public class LocalSecurityConfig {

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

    @Bean
    @Order(2)
    public SecurityFilterChain localSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .securityMatcher("/**")

            // --- CRITICAL LOCAL OVERRIDE ---
            // OVERRIDE: Allow HTTP for local testing
            .requiresChannel(channel -> channel.anyRequest().requiresInsecure())
            // --- CRITICAL LOCAL OVERRIDE ---

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
