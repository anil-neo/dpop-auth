
package com.neoteric.dpop.core.token.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.neoteric.dpop.core.token.model.ClientDetails;
import com.neoteric.dpop.core.token.model.Token;
import com.neoteric.dpop.core.token.model.ValidationRequest;
import com.neoteric.dpop.core.token.service.TokenService;
import com.neoteric.dpop.core.utils.BindingStore;
import com.neoteric.dpop.core.utils.DPoPVerifier;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DPoPTestController {
    private final DPoPVerifier verifier;
    private final BindingStore bindingStore;
    private final TokenService tokenService;

    @Value("${neoteric.jwt-app.client-id}")
    private String clientId;

    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("cnf") Map<String, String> cnf
    ) {
    }

    @GetMapping("/token")
    public ResponseEntity<?> token(@RequestHeader("DPoP") String dpop, HttpServletRequest req) {
        try {
            var result = verifier.verifyProof(dpop, req, null);

            // Replay prevention
            String jti = result.claims().getStringClaim("jti");
            if (!bindingStore.rememberJti(jti, 300)) {
                log.warn("DPoP replay detected for jti={}", jti);
                return ResponseEntity.status(401)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(Map.of("error", "DPoP replay detected"));
            }

            // Compute jkt
            String jkt = DPoPVerifier.jktThumbprint((ECKey) result.jwk());
            log.info("Generated jkt={} for DPoP proof", jkt);

            // Generate token with clientId
            ClientDetails clientDetails = new ClientDetails();
            clientDetails.setClientId(clientId); // Use configured clientId from properties
            clientDetails.setType("dpop"); // Set a type if needed for TokenService
            Token token = tokenService.generateToken(clientDetails);
            if (token == null) {
                log.error("Failed to generate token for clientId={}", clientDetails.getClientId());
                return ResponseEntity.status(400)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(Map.of("error", "Invalid client credentials"));
            }

            // Bind token to jkt
            bindingStore.bind(token.getToken(), jkt);
            log.info("Bound token={} to jkt={}", token.getToken(), jkt);

            return ResponseEntity.ok(new TokenResponse(
                    token.getToken(), "DPoP", 90000, Map.of("jkt", jkt)
            ));
        } catch (Exception e) {
            log.error("Error processing /api/token: {}", e.getMessage(), e);
            return ResponseEntity.status(401)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", "Invalid DPoP proof: " + e.getMessage()));
        }
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "time", Instant.now().toString(), "id", UUID.randomUUID().toString());
    }

    @PostMapping(value = "/validate-app-token", consumes = "application/json")
    public ResponseEntity<?> validateToken(@RequestBody ValidationRequest validationRequest) {
        log.info("Entering validateToken: validating the mobile-app token for the request={},userId={}",
                validationRequest, validationRequest.getUserId());
        ClientDetails clientDetails = new ClientDetails();
        clientDetails.setClientId(clientId); // Use configured clientId from properties
        clientDetails.setType("dpop");

        validationRequest.setClientDetails(clientDetails);
        String token = tokenService.validateAndRefreshToken(validationRequest);
        return ResponseEntity.ok("Token is valid: " + token);
    }
}
