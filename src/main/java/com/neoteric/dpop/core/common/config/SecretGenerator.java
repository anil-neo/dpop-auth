//package com.neoteric.dpop.core.common.config;
//
//import io.jsonwebtoken.io.Encoders;
//import io.jsonwebtoken.security.Keys;
//
//import javax.crypto.SecretKey;
//
//public class SecretGenerator {
//    public static void main(String[] args) {
//        SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
//        String base64Key = Encoders.BASE64.encode(key.getEncoded());
//        System.out.println(base64Key);
//    }
//}
