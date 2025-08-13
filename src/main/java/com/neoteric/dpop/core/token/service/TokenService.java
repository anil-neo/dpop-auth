package com.neoteric.dpop.core.token.service;

import com.neoteric.dpop.core.token.entity.ClientDetailsEntity;
import com.neoteric.dpop.core.token.entity.TokenEntity;
import com.neoteric.dpop.core.token.model.ClientDetails;
import com.neoteric.dpop.core.token.model.Token;
import com.neoteric.dpop.core.token.model.ValidationRequest;
import com.neoteric.dpop.core.token.repo.ClientRepository;
import com.neoteric.dpop.core.token.repo.TokenRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class TokenService {

    private final TokenRepository tokenRepository;
    private final ClientRepository clientRepository;
    private final SecretKey jwtSecret;

    // Config
    private static final long TOKEN_EXPIRY_IN_DAYS = 30;
    private static final long SERVICE_TOKEN_EXPIRATION = TOKEN_EXPIRY_IN_DAYS * 24 * 60 * 60 * 1000L; // ms

    @Value("${neoteric.jwt-app.client-id}")
    private String clientId;

    public TokenService(TokenRepository tokenRepository,
                        ClientRepository clientRepository) {
        this.tokenRepository = tokenRepository;
        this.clientRepository = clientRepository;

        // Hardcode the Base64 secret key for now
        String base64Secret = "+Xk0GEnru5FtxV197314mwSjfIQyFNXfU55BpwJda4c=";
        this.jwtSecret = Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(base64Secret));
    }

    /**
     * Generate JWT token for a client and save in DB.
     */
    @Transactional
    public Token generateToken(ClientDetails clientDetails) {
        log.info("Generating token for clientId={}", clientDetails.getClientId());

        Optional<ClientDetailsEntity> clientOpt = clientRepository.findByClientId(clientDetails.getClientId());
        if (clientOpt.isEmpty()) {
            log.error("Invalid clientId={}", clientDetails.getClientId());
            return null;
        }

        String requesterId = UUID.randomUUID().toString();
        String tokenValue = Jwts.builder()
                .subject(requesterId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + SERVICE_TOKEN_EXPIRATION))
                .signWith(jwtSecret)
                .compact();

        TokenEntity tokenEntity = new TokenEntity();
        tokenEntity.setClientId(clientDetails.getClientId());
        tokenEntity.setToken(tokenValue);
        tokenEntity.setRequesterId(requesterId);
        tokenEntity.setCreatedAt(Instant.now());
        tokenEntity.setExpiredAt(Instant.now().plus(TOKEN_EXPIRY_IN_DAYS, ChronoUnit.DAYS));
        tokenEntity.setType(clientDetails.getType());

        tokenRepository.save(tokenEntity);

        Token response = new Token();
        response.setToken(tokenValue);
        return response;
    }

    /**
     * Validate a token. Optionally refresh if expired/near expiry.
     */
    @Transactional
    public String validateAndRefreshToken(ValidationRequest request) {
        log.info("Validating token for clientId={}, token={}",
                request.getClientDetails().getClientId(), request.getToken());

        Optional<TokenEntity> tokenEntityOpt = tokenRepository.findByToken(request.getToken());
        if (tokenEntityOpt.isEmpty()) {
            log.error("Invalid token={}", request.getToken());
            return null;
        }

        TokenEntity tokenEntity = tokenEntityOpt.get();
        Instant now = Instant.now();

        // Refresh if expired or less than 24h left
        if (tokenEntity.getExpiredAt().isBefore(now) ||
                ChronoUnit.HOURS.between(now, tokenEntity.getExpiredAt()) < 24) {
            log.info("Token expired or near expiry, refreshing...");
            Token refreshed = generateToken(request.getClientDetails());
            return refreshed != null ? refreshed.getToken() : null;
        }

        return request.getToken();
    }

    /**
     * Find a token. If expired and endpoint is /validate-app-token, regenerate it.
     */
    public Optional<TokenEntity> findByToken(String token, String uri) {
        Optional<TokenEntity> tokenEntityOpt = tokenRepository.findByToken(token);

        if (tokenEntityOpt.isPresent() && tokenEntityOpt.get().getExpiredAt().isAfter(Instant.now())) {
            return tokenEntityOpt;
        }

        if (uri.contains("/validate-app-token")) {
            log.info("Token expired, regenerating for /validate-app-token");
            ClientDetails clientDetails = new ClientDetails();
            clientDetails.setClientId(clientId);
            Token newToken = generateToken(clientDetails);
            return tokenRepository.findByToken(newToken.getToken());
        }

        return Optional.empty();
    }
}
