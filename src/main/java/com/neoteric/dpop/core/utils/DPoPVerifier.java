package com.neoteric.dpop.core.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;

@Component
public class DPoPVerifier {

    public record Result(JWK jwk, JWTClaimsSet claims) {}

    public Result verifyProof(String dpopJwt, HttpServletRequest req, String accessTokenIfAny) {
        try {
            SignedJWT jwt = SignedJWT.parse(dpopJwt);

            // Header checks
            JWSHeader hdr = jwt.getHeader();
            if (hdr.getType() == null || !"dpop+jwt".equalsIgnoreCase(hdr.getType().toString())) {
                throw new JOSEException("typ must be dpop+jwt");
            }
            JWK jwk = hdr.getJWK();
            if (jwk == null) throw new JOSEException("Missing JWK in header");
            if (!(KeyType.EC.equals(jwk.getKeyType()) && "P-256".equals(((ECKey) jwk).getCurve().getName()))) {
                throw new JOSEException("Only EC P-256 supported in this demo");
            }

            // Signature
            JWSVerifier verifier = new ECDSAVerifier(((ECKey) jwk).toECPublicKey());
            if (!jwt.verify(verifier)) throw new JOSEException("Invalid DPoP signature");

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // htm
            String htm = claims.getStringClaim("htm");
            if (htm == null || !htm.equalsIgnoreCase(req.getMethod())) throw new JOSEException("htm mismatch");

            // htu (scheme/host/port/path match; query excluded)
            URI reqUri = URI.create(req.getRequestURL().toString());
            URI htu = URI.create(claims.getStringClaim("htu"));
            if (!eq(reqUri.getScheme(), htu.getScheme()) ||
                    !eq(reqUri.getHost(), htu.getHost()) ||
                    normPort(reqUri) != normPort(htu) ||
                    !eq(reqUri.getPath(), htu.getPath())) {
                throw new JOSEException("htu mismatch");
            }

            // iat (5 min skew)
            Date iat = claims.getDateClaim("iat");
            if (iat == null) throw new JOSEException("missing iat");
            Instant now = Instant.now();
            Instant i = iat.toInstant();
            if (i.isBefore(now.minusSeconds(300)) || i.isAfter(now.plusSeconds(5))) {
                throw new JOSEException("iat out of range");
            }

            // ath if access token present (resource call)
            if (accessTokenIfAny != null && !accessTokenIfAny.isBlank()) {
                String ath = claims.getStringClaim("ath");
                if (ath == null || !ath.equals(sha256b64u(accessTokenIfAny))) {
                    throw new JOSEException("ath mismatch");
                }
            }
            // jti presence (replay protection is in filter using BindingStore)
            if (claims.getStringClaim("jti") == null) throw new JOSEException("missing jti");

            return new Result(jwk, claims);

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static String jktThumbprint(ECKey ecKey) throws JOSEException {
        Base64URL thumb = ecKey.computeThumbprint("SHA-256");
        return thumb.toString(); // base64url
    }

    public static String sha256b64u(String s) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] h = d.digest(s.getBytes(StandardCharsets.UTF_8));
        return Base64URL.encode(h).toString();
    }

    private static boolean eq(String a, String b) { return (a == null && b == null) || (a != null && a.equalsIgnoreCase(b)); }
    private static int normPort(URI u) {
        if (u.getPort() != -1) return u.getPort();
        return switch (u.getScheme()) { case "http" -> 80; case "https" -> 443; default -> -1; };
    }
}
