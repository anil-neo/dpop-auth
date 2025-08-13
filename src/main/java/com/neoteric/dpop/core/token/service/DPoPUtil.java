package com.neoteric.dpop.core.token.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class DPoPUtil {
    public static RSAKey generateRsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    public static String b64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static String sha256B64Url(String s) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return b64Url(h);
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    public static String createDpopProof(RSAKey rsaKey, String method, String uri, String accessToken) throws JOSEException {
        JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder()
                .claim("htu", uri)
                .claim("htm", method)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString());
        if (accessToken != null) cb.claim("ath", sha256B64Url(accessToken));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(rsaKey.toPublicJWK())
                .build();

        SignedJWT jwt = new SignedJWT(header, cb.build());
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }
}
