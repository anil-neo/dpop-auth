//package com.neoteric.dpop.core.common.config;
//
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import javax.crypto.SecretKey;
//import javax.crypto.spec.SecretKeySpec;
//import java.util.Base64;
//
//@Configuration
//public class JwtConfig {
//
//    @Value("${jwt.secret.base64}")
//    private String jwtSecretBase64;
//
//    @Bean
//    public SecretKey jwtSecretKey() {
//        byte[] decodedKey = Base64.getDecoder().decode(jwtSecretBase64);
//        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
//    }
//}
