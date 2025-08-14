//package com.neoteric.dpop.core.token.filter;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.neoteric.dpop.core.token.entity.TokenEntity;
//import com.neoteric.dpop.core.token.service.TokenService;
//import com.nimbusds.jose.JOSEException;
//import com.nimbusds.jose.JWSVerifier;
//import com.nimbusds.jose.crypto.ECDSAVerifier;
//import com.nimbusds.jose.crypto.RSASSAVerifier;
//import com.nimbusds.jose.jwk.ECKey;
//import com.nimbusds.jose.jwk.JWK;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jwt.JWTClaimsSet;
//import com.nimbusds.jwt.SignedJWT;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.net.URI;
//import java.nio.charset.StandardCharsets;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.time.Instant;
//import java.util.Base64;
//import java.util.Map;
//import java.util.Optional;
//
//@Component
//@Slf4j
//public class JwtTokenFilter extends OncePerRequestFilter {
//
//    private final TokenService tokenService;
//    private final ObjectMapper objectMapper;
//
//    public JwtTokenFilter(TokenService tokenService, ObjectMapper objectMapper) {
//        this.tokenService = tokenService;
//        this.objectMapper = objectMapper;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//        String uri = request.getRequestURI();
//
//        // Skip public APIs
//        if (isPublicEndpoint(uri)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        // Extract headers
//        String authHeader = request.getHeader("Authorization");
//        String dpopProof = request.getHeader("DPoP");
//
//        if (authHeader == null || dpopProof == null) {
//            sendUnauthorized(response, "Missing Authorization or DPoP header");
//            return;
//        }
//
//        // Remove "DPoP " prefix from Authorization token
//        String accessToken = authHeader.replaceFirst("(?i)^DPoP\\s+", "").trim();
//
//        // Validate token from DB
//        Optional<TokenEntity> tokenEntity = tokenService.findByToken(accessToken, uri);
//        if (tokenEntity.isEmpty() || tokenEntity.get().getExpiredAt().isBefore(Instant.now())) {
//            sendUnauthorized(response, "Invalid or expired token");
//            return;
//        }
//
//        // Validate DPoP proof
//        try {
//            validateDpopProof(dpopProof, request, accessToken);
//        } catch (Exception e) {
//            log.warn("DPoP validation failed: {}", e.getMessage());
//            sendUnauthorized(response, "Invalid DPoP proof: " + e.getMessage());
//            return;
//        }
//
//        // Continue request
//        filterChain.doFilter(request, response);
//    }
//
//    private void validateDpopProof(String dpopProof, HttpServletRequest request, String accessToken) {
//        try {
//            SignedJWT jwt = SignedJWT.parse(dpopProof);
//
//            // Extract public key from header
//            JWK jwk = jwt.getHeader().getJWK();
//            if (jwk == null) throw new RuntimeException("Missing JWK in DPoP proof");
//
//            // Choose verifier
//            JWSVerifier verifier;
//            if (jwk instanceof RSAKey rsaKey) {
//                verifier = new RSASSAVerifier(rsaKey);
//            } else if (jwk instanceof ECKey ecKey) {
//                verifier = new ECDSAVerifier(ecKey);
//            } else {
//                throw new RuntimeException("Unsupported JWK key type: " + jwk.getKeyType());
//            }
//
//            if (!jwt.verify(verifier)) throw new RuntimeException("Invalid DPoP signature");
//
//            JWTClaimsSet claims = jwt.getJWTClaimsSet();
//
//            // 1️⃣ HTTP Method check
//            String method = claims.getStringClaim("htm");
//            if (method == null || !method.equalsIgnoreCase(request.getMethod()))
//                throw new RuntimeException("HTTP method mismatch");
//
//            // 2️⃣ URI check (ignore query params)
//            URI requestUri = URI.create(request.getRequestURL().toString());
//            URI proofUri = URI.create(claims.getStringClaim("htu"));
//            if (!requestUri.getScheme().equalsIgnoreCase(proofUri.getScheme())
//                    || !requestUri.getHost().equalsIgnoreCase(proofUri.getHost())
//                    || !requestUri.getPath().equals(proofUri.getPath())) {
//                throw new RuntimeException("HTTP URI mismatch");
//            }
//
//            // 3️⃣ Issued-at check (within 5 min)
//            Instant issuedAt = claims.getDateClaim("iat").toInstant();
//            Instant now = Instant.now();
//            if (issuedAt.isBefore(now.minusSeconds(300)) || issuedAt.isAfter(now.plusSeconds(5)))
//                throw new RuntimeException("DPoP proof time invalid");
//
//            // 4️⃣ Access Token hash check
//            String expectedAth = hashAccessToken(accessToken);
//            if (!expectedAth.equals(claims.getStringClaim("ath")))
//                throw new RuntimeException("Access token hash mismatch");
//
//        } catch (java.text.ParseException e) {
//            throw new RuntimeException("Invalid DPoP proof format");
//        } catch (JOSEException e) {
//            throw new RuntimeException("DPoP verification error: " + e.getMessage());
//        }
//    }
//
//    private String hashAccessToken(String accessToken) {
//        try {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
//            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("Unable to hash token", e);
//        }
//    }
//
//    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//        objectMapper.writeValue(response.getWriter(),
//                Map.of("status", "Unauthorized", "message", message));
//    }
//
//    private boolean isPublicEndpoint(String uri) {
//        return uri.contains("/api/neoteric/generate-token")
//                || uri.contains("/api/neoteric/generateDeviceToken")
//                || uri.contains("/health");
//    }
//}
