package com.neoteric.dpop.core.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum NeoErrors {

    /**
     * Error code and message for DPoP verification errors.
     */

    ONLY_EC_P256_SUPPORTED("Only EC P-256 supported in this implementation","9001"),
    TYP("typ must be dpop+jwt", "9002"),
    MISSING_JWK("Missing JWK in header", "9003"),
    INVALID_SIGNATURE("Invalid DPoP signature", "9004"),
    HTM_MISMATCH("htm mismatch", "9005"),
    HTU_MISMATCH("htu mismatch", "9006"),
    MISSING_IAT("missing iat", "9007"),
    IAT_OUT_OF_RANGE("iat out of range", "9008"),
    ATH_MISMATCH("ath mismatch", "9009"),
    MISSING_JTI("missing jti", "9010"),;

    final String message;
    final String code;
}
