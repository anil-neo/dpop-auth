package com.neoteric.dpop.core.token.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.neoteric.dpop.core.utils.BindingStore;
import com.neoteric.dpop.core.utils.DPoPVerifier;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class TokenControllerDemo {
    private final DPoPVerifier verifier;
    private final BindingStore bindingStore;

    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("cnf") Map<String,String> cnf
    ) {}

    /** Token endpoint expects DPoP proof for POST /api/token (htm/htu/iat/jti) */
    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestHeader("DPoP") String dpop, HttpServletRequest req) throws Exception {
        var result = verifier.verifyProof(dpop, req, null);

        // Replay prevent on token endpoint too
        String jti = result.claims().getStringClaim("jti");
        if (!bindingStore.rememberJti(jti, 300)) {
            return ResponseEntity.status(401).body(Map.of("error","DPoP replay detected"));
        }

        // Compute jkt and bind token → jkt
        String jkt = DPoPVerifier.jktThumbprint((ECKey) result.jwk());
        String accessToken = BindingStore.newToken();
        bindingStore.bind(accessToken, jkt);

        // (Optionally) include cnf.jkt inside a JWT access token. Here we keep token opaque and return cnf separately.
        return ResponseEntity.ok(new TokenResponse(
                accessToken, "DPoP", 900, Map.of("jkt", jkt)
        ));
    }

    @GetMapping("/health")
    public Map<String,Object> health() {
        return Map.of("status","ok","time", Instant.now().toString(), "id", UUID.randomUUID().toString());
    }
}
