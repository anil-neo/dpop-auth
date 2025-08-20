
package com.neoteric.dpop.core.token.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neoteric.dpop.core.token.service.TokenService;
import com.neoteric.dpop.core.utils.BindingStore;
import com.neoteric.dpop.core.utils.DPoPVerifier;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class DPoPFilter extends OncePerRequestFilter {
    private final DPoPVerifier verifier;
    private final BindingStore bindingStore;
    private final TokenService tokenService;
    private final ObjectMapper om = new ObjectMapper();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        String p = req.getRequestURI();
        return p.startsWith("/api/token") || p.startsWith("/health") || p.startsWith("/api/neoteric");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(req, res);
            return;
        }
        try {
            String dpop = req.getHeader("DPoP");
            String auth = req.getHeader("Authorization");

            if (dpop == null || auth == null || !auth.toLowerCase().startsWith("dpop ")) {
                reject(res, 401, "Missing DPoP or Authorization header");
                return;
            }
            String accessToken = auth.substring(5).trim();
            log.info("Incoming DPoP check: method={}, uri={}, token={}, dpopJWT={}",
                    req.getMethod(), req.getRequestURL(), accessToken, dpop);

            // Validate token against TokenRepository
            var tokenEntity = tokenService.findByToken(accessToken, req.getRequestURI());
            if (tokenEntity.isEmpty()) {
                log.error("Invalid or expired token: {}", accessToken);
                reject(res, 401, "Invalid or expired token");
                return;
            }

            var result = verifier.verifyProof(dpop, req, accessToken);

            // Replay prevention: jti TTL 5 minutes
            String jti = result.claims().getStringClaim("jti");
            if (!bindingStore.rememberJti(jti, 300)) {
                reject(res, 401, "DPoP replay detected");
                return;
            }

            // Compare jkt from proof header JWK vs token binding
            String boundJkt = bindingStore.getJkt(accessToken);
            if (boundJkt == null) {
                reject(res, 401, "Unknown access token");
                return;
            }
            String proofJkt = DPoPVerifier.jktThumbprint((ECKey) result.jwk());
            if (!boundJkt.equals(proofJkt)) {
                reject(res, 401, "Key binding mismatch");
                log.info("Verified proof: jti={}, boundJkt={}, proofJkt={}, ath={}",
                        jti, boundJkt, proofJkt, result.claims().getStringClaim("ath"));

                return;
            }

            // Set Authentication in SecurityContext
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    tokenEntity.get().getClientId(), null, Collections.emptyList() // Add authorities/scopes if needed
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("Authentication set for clientId: {}", tokenEntity.get().getClientId());

            chain.doFilter(req, res);
        } catch (Exception e) {
            log.warn("DPoP filter rejected: {}", e.getMessage());
            reject(res, 401, "Invalid DPoP proof: " + e.getMessage());
        }
    }

    private void reject(HttpServletResponse res, int code, String msg) throws IOException {
        res.setStatus(code);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        om.writeValue(res.getWriter(), Map.of("error", msg));
    }
}
