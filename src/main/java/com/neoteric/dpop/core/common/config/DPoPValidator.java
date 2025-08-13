//package com.neoteric.dpop.core.common.config;
//
//
//
//import com.nimbusds.jose.JWSObject;
//import com.nimbusds.jwt.SignedJWT;
//import org.springframework.stereotype.Component;
//
//import java.text.ParseException;
//
//@Component
//public class DPoPValidator {
//
//    public boolean validateProof(String dpopProof, String accessToken) throws ParseException {
//        // Parse DPoP Proof
//        JWSObject proofObject = JWSObject.parse(dpopProof);
//        String proofJwkThumbprint = (String) proofObject.getPayload().toJSONObject().get("jwk");
//
//        // Parse Access Token
//        SignedJWT jwt = SignedJWT.parse(accessToken);
//        String tokenCnf = (String) jwt.getJWTClaimsSet().getClaim("cnf");
//
//        return proofJwkThumbprint != null && proofJwkThumbprint.equals(tokenCnf);
//    }
//}
//
