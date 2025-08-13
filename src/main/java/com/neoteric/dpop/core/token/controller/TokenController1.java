package com.neoteric.dpop.core.token.controller;

import com.neoteric.dpop.core.token.entity.TokenEntity;
import com.neoteric.dpop.core.token.service.TokenService1;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class TokenController1 {
    private final TokenService1 tokenService;

    // Steps 6–10: Token issuance with DPoP proof verification
    @PostMapping("/generate-token")
    public ResponseEntity<?> issueToken(@RequestHeader("DPoP") String dpopProof) throws JOSEException, ParseException {
        SignedJWT proof = SignedJWT.parse(dpopProof);

        JWK jwk = proof.getHeader().getJWK();
        if (jwk == null) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_dpop", "message", "Missing JWK in DPoP header"));
        }

        RSAKey rsaKey = jwk.toRSAKey();
        RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
        if (!proof.verify(verifier)) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_dpop", "message", "Invalid DPoP signature"));
        }

        // Optional: enforce htm/htu for this endpoint
        JWTClaimsSet claims = proof.getJWTClaimsSet();
        String htm = String.valueOf(claims.getClaim("htm"));
        String htu = String.valueOf(claims.getClaim("htu"));
        if (!"POST".equalsIgnoreCase(htm)) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_dpop", "message", "htm must be POST"));
        }
        // NOTE: In prod, compare absolute URL. For demo we accept any htu.

        String tokenValue = UUID.randomUUID().toString();
        Instant expiry = Instant.now().plusSeconds(3600);

        TokenEntity entity = tokenService.issueAccessToken(jwk.toJSONString(), tokenValue, expiry);

        return ResponseEntity.ok(Map.of(
                "access_token", entity.getToken(),
                "token_type", "DPoP",
                "expires_in", 3600
        ));
    }
}
