package com.neoteric.dpop.core.token.service;

import com.neoteric.dpop.core.token.entity.TokenEntity;
import com.neoteric.dpop.core.token.model.AppLoadResponse;
import com.neoteric.dpop.core.token.model.ClientDetails;
import com.neoteric.dpop.core.token.model.ValidationRequest;
import com.neoteric.dpop.core.token.repo.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService1 {

    private final TokenRepository tokenRepository;


    @Override
    public Optional<TokenEntity> findByToken(String token) {
        return tokenRepository.findByToken(token);
    }

    @Override
    public Optional<String> getPublicKeyForToken(String token) {
        return tokenRepository.findByToken(token).map(TokenEntity::getPublicKeyJwk);
    }

    @Override
    public TokenEntity issueAccessToken(String publicKeyJwk, String tokenValue, Instant expiry) {
        TokenEntity e = new TokenEntity();
        e.setToken(tokenValue != null ? tokenValue : UUID.randomUUID().toString());
        e.setPublicKeyJwk(publicKeyJwk);
        e.setExpiredAt(expiry);
        return tokenRepository.save(e);
    }
}
