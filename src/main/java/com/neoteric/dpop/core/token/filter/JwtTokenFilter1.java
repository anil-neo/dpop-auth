package com.neoteric.dpop.core.token.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neoteric.dpop.core.token.entity.TokenEntity;
import com.neoteric.dpop.core.token.service.TokenService1;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenFilter1 extends OncePerRequestFilter {
    private final TokenService1 tokenService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();

        // Always allow health
        if (uri.contains("/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Special handling for token issuance endpoint: verify DPoP proof ONLY (no access token yet)
        if (uri.contains("/api/generate-token")) {
            String dpopProof = request.getHeader("DPoP");
            if (dpopProof == null) {
                sendUnauthorized(response, "missing_dpop", "Missing DPoP header");
                return;
            }
            try {
                validateDpopProofForTokenRequest(dpopProof, request);
            } catch (Exception e) {
                log.warn("DPoP token request validation failed: {}", e.getMessage());
                sendUnauthorized(response, "invalid_dpop", e.getMessage());
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        // For all other endpoints: require Authorization: DPoP <token> and DPoP proof for API call
        String authz = request.getHeader("Authorization");
        String dpopProof = request.getHeader("DPoP");

        if (authz == null || dpopProof == null) {
            sendUnauthorized(response, "missing_headers", "Missing Authorization or DPoP header");
            return;
        }

        String accessToken = authz.replaceFirst("(?i)^DPoP\s+", "").trim();
        if (accessToken.isEmpty()) {
            sendUnauthorized(response, "invalid_authorization", "Empty access token");
            return;
        }

        Optional<TokenEntity> tokenEntityOpt = tokenService.findByToken(accessToken);
        if (tokenEntityOpt.isEmpty()) {
            sendUnauthorized(response, "invalid_token", "Unknown access token");
            return;
        }

        TokenEntity tokenEntity = tokenEntityOpt.get();
        if (tokenEntity.getExpiredAt() == null || tokenEntity.getExpiredAt().isBefore(Instant.now())) {
            sendUnauthorized(response, "token_expired", "Expired access token");
            return;
        }

        try {
            validateDpopProofForApi(dpopProof, request, accessToken, tokenEntity.getPublicKeyJwk());
        } catch (Exception e) {
            log.warn("DPoP API validation failed: {}", e.getMessage());
            sendUnauthorized(response, "dpop_verification_failed", e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void validateDpopProofForTokenRequest(String dpopProof, HttpServletRequest request) {
        try {
            SignedJWT jwt = SignedJWT.parse(dpopProof);
            JWK jwk = jwt.getHeader().getJWK();
            if (jwk == null) throw new RuntimeException("Missing JWK in DPoP proof");

            RSAKey rsaKey = jwk.toRSAKey();
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
            if (!jwt.verify(verifier)) throw new RuntimeException("Invalid DPoP signature");

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            String method = strClaim(claims, "htm");
            if (!"POST".equalsIgnoreCase(method)) throw new RuntimeException("htm must be POST");

            String htu = strClaim(claims, "htu");
            if (htu == null) throw new RuntimeException("Missing 'htu' claim");

            URI actualUri = URI.create(request.getRequestURL().toString());
            URI proofUri = URI.create(htu);
            if (!eq(actualUri.getScheme(), proofUri.getScheme()) ||
                    !eq(actualUri.getHost(), proofUri.getHost()) ||
                    normPort(actualUri) != normPort(proofUri) ||
                    !eq(actualUri.getPath(), proofUri.getPath())) {
                throw new RuntimeException("HTTP URI mismatch");
            }

            Instant issuedAt = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : null;
            if (issuedAt == null) throw new RuntimeException("Missing 'iat' claim");
            Instant now = Instant.now();
            if (issuedAt.isBefore(now.minusSeconds(300)) || issuedAt.isAfter(now.plusSeconds(5))) {
                throw new RuntimeException("DPoP proof time invalid");
            }

            if (claims.getClaim("ath") != null) {
                // For token request, 'ath' is typically absent; allow but ignore
            }
        } catch (java.text.ParseException e) {
            throw new RuntimeException("Invalid DPoP proof format");
        } catch (JOSEException e) {
            throw new RuntimeException("JWK/Signature processing error: " + e.getMessage());
        }
    }

    private void validateDpopProofForApi(String dpopProof, HttpServletRequest request, String accessToken, String boundPublicJwk) {
        try {
            SignedJWT jwt = SignedJWT.parse(dpopProof);
            JWK jwk = jwt.getHeader().getJWK();
            if (jwk == null) throw new RuntimeException("Missing JWK in DPoP proof");

            RSAKey rsaKey = jwk.toRSAKey();
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
            if (!jwt.verify(verifier)) throw new RuntimeException("Invalid DPoP signature");

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String method = strClaim(claims, "htm");
            if (method == null || !method.equalsIgnoreCase(request.getMethod())) throw new RuntimeException("HTTP method mismatch");

            String htu = strClaim(claims, "htu");
            if (htu == null) throw new RuntimeException("Missing 'htu' claim");

            URI actualUri = URI.create(request.getRequestURL().toString());
            URI proofUri = URI.create(htu);
            if (!eq(actualUri.getScheme(), proofUri.getScheme()) ||
                    !eq(actualUri.getHost(), proofUri.getHost()) ||
                    normPort(actualUri) != normPort(proofUri) ||
                    !eq(actualUri.getPath(), proofUri.getPath())) {
                throw new RuntimeException("HTTP URI mismatch");
            }

            Instant issuedAt = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : null;
            if (issuedAt == null) throw new RuntimeException("Missing 'iat' claim");
            Instant now = Instant.now();
            if (issuedAt.isBefore(now.minusSeconds(300)) || issuedAt.isAfter(now.plusSeconds(5))) {
                throw new RuntimeException("DPoP proof time invalid");
            }

            String ath = strClaim(claims, "ath");
            if (ath == null) throw new RuntimeException("Missing 'ath' claim");
            String expectedAth = hashAccessToken(accessToken);
            if (!expectedAth.equals(ath)) throw new RuntimeException("Access token hash mismatch");

            if (boundPublicJwk == null || boundPublicJwk.isBlank()) throw new RuntimeException("No public key bound to access token");
            String proofJwkJson = jwk.toJSONString();
            if (!proofJwkJson.equals(boundPublicJwk)) throw new RuntimeException("DPoP public key does not match bound access token key");

        } catch (java.text.ParseException e) {
            throw new RuntimeException("Invalid DPoP proof format");
        } catch (JOSEException e) {
            throw new RuntimeException("JWK/Signature processing error: " + e.getMessage());
        }
    }

    private static String strClaim(JWTClaimsSet claims, String name) {
        Object v = claims.getClaim(name);
        return v == null ? null : String.valueOf(v);
    }

    private static boolean eq(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equalsIgnoreCase(b);
    }

    private static int normPort(URI u) {
        int p = u.getPort();
        if (p != -1) return p;
        if ("https".equalsIgnoreCase(u.getScheme())) return 443;
        if ("http".equalsIgnoreCase(u.getScheme())) return 80;
        return -1;
    }

    private String hashAccessToken(String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to hash token", e);
        }
    }

    private void sendUnauthorized(HttpServletResponse response, String errorCode, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader("WWW-Authenticate", "DPoP error=\"" + errorCode + "\", error_description=\"" + message + "\"");
        objectMapper.writeValue(response.getWriter(), Map.of(
                "status", "Unauthorized",
                "error", errorCode,
                "message", message
        ));
    }
}
