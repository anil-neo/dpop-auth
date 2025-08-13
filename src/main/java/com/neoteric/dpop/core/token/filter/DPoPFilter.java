package com.neoteric.dpop.core.token.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class DPoPFilter extends OncePerRequestFilter {
    private final DPoPVerifier verifier;
    private final BindingStore bindingStore;
    private final ObjectMapper om = new ObjectMapper();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        String p = req.getRequestURI();
        return p.startsWith("/api/token") || p.startsWith("/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        try {
            String dpop = req.getHeader("DPoP");
            String auth = req.getHeader("Authorization");
            if (dpop == null || auth == null || !auth.toLowerCase().startsWith("dpop ")) {
                reject(res, 401, "Missing DPoP or Authorization header");
                return;
            }
            String accessToken = auth.substring(5).trim();

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
                return;
            }

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
