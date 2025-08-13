package com.neoteric.dpop.core.common.config;

import com.neoteric.dpop.core.token.filter.DPoPFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    private final JwtTokenFilter jwtTokenFilter;
//
//    public SecurityConfig(JwtTokenFilter jwtTokenFilter) {
//        this.jwtTokenFilter = jwtTokenFilter;
//    }
//    @Bean
//    public CorsFilter corsFilter() {
//        CorsConfiguration config = new CorsConfiguration();
//        config.addAllowedOrigin("http://localhost:3000"); // frontend origin
//        config.addAllowedHeader("*"); // allow all headers
//        config.addAllowedMethod("*"); // GET, POST, etc.
//        config.setAllowCredentials(true); // if cookies or auth needed
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", config);
//        return new CorsFilter(source);
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .cors() // Enable CORS
//                .and()
//                .csrf().disable() // DPoP or JWT, no CSRF required
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/api/neoteric/generate-token", "/api/neoteric/generateDeviceToken", "/health")
//                        .permitAll()
//                        .anyRequest().authenticated()
//                );
//        return http.build();
//    }

    private final DPoPFilter dPoPFilter;

    public SecurityConfig(DPoPFilter dPoPFilter) {
        this.dPoPFilter = dPoPFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/token", "/health").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(dPoPFilter, AnonymousAuthenticationFilter.class);
        return http.build();
    }
}
