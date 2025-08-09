package com.neoteric.dpop.core.common.security;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Class to generate MasterKey and Salt
 */
public abstract class MasterKeyGenerator {

    public static String generateMasterKey(int byteLength) {
        return generateSecureRandom(byteLength);
    }

    public static String randomSalt(int byteLength) {
        return generateSecureRandom(byteLength);
    }

    private static String generateSecureRandom(int byteLength) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[byteLength];
        random.nextBytes(salt);
        return new BigInteger(1, salt).toString(16);
    }

    public static void main(String[] args) {
        /*System.out.println(generateMasterKey(16));
        System.out.println(randomSalt(16));*/
        System.out.println(encodeToBase64("ANI"));
    }

    public static String encodeToBase64(String message) {
        return Base64.getEncoder().encodeToString(message.getBytes());
    }
}