package com.neoteric.dpop.core.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NeotericConstants {

    // Base64 encoded secret key for HMAC signing
    public static final String BASE64SECRET = "+Xk0GEnru5FtxV197314mwSjfIQyFNXfU55BpwJda4c=";

    public static final String HASH_ALGORITHM = "SHA-256";

}
