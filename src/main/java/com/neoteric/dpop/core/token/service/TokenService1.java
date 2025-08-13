package com.neoteric.dpop.core.token.service;

import com.neoteric.dpop.core.token.entity.TokenEntity;

import java.time.Instant;
import java.util.Optional;

public interface TokenService1 {
    Optional<TokenEntity> findByToken(String token);
    Optional<String> getPublicKeyForToken(String token);
    TokenEntity issueAccessToken(String publicKeyJwk, String tokenValue, Instant expiry);
}


