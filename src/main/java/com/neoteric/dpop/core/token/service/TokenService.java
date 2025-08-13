package com.neoteric.dpop.core.token.service;

import com.neoteric.dpop.core.token.entity.ClientDetailsEntity;
import com.neoteric.dpop.core.token.entity.TokenEntity;
import com.neoteric.dpop.core.token.model.ClientDetails;
import com.neoteric.dpop.core.token.model.Token;
import com.neoteric.dpop.core.token.model.ValidationRequest;
import com.neoteric.dpop.core.token.repo.ClientRepository;
import com.neoteric.dpop.core.token.repo.TokenRepository;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class TokenService {

    @Value("${neoteric.jwt-app.client-id}")
    private String clientId;

    private final String secretKey;
    private final TokenRepository tokenRepository;
    private final ClientRepository clientRepository;
    private final SecretKeySpec jwtSecret;

    private static final long TOKEN_EXPIRY_IN_DAYS = 30;
    private static final long SERVICE_TOKEN_EXPIRATION = 86400000L * TOKEN_EXPIRY_IN_DAYS; // 30 days
    private static final String ALGORITHM = "HmacSHA256";

    public TokenService(TokenRepository tokenRepository,
                        ClientRepository clientRepository,
                        @Value("${neoteric.jwt-app.secret}") String secretKey) {
        this.tokenRepository = tokenRepository;
        this.clientRepository = clientRepository;
        this.secretKey = secretKey;
        this.jwtSecret = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    /**
     * GenerCorsConfigate token for a client.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public Token generateToken(ClientDetails clientDetails) {
        log.info("Generating token for clientId={}", clientDetails.getClientId());

        Optional<ClientDetailsEntity> clientOpt = clientRepository.findByClientId(clientDetails.getClientId());
        if (clientOpt.isEmpty()) {
            log.error("Invalid clientId={}", clientDetails.getClientId());
            return null;
        }

        String requesterId = UUID.randomUUID().toString();
        String tokenValue = Jwts.builder()
                .claims()
                .subject(requesterId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + SERVICE_TOKEN_EXPIRATION))
                .and()
                .signWith(jwtSecret)
                .compact();

        TokenEntity clientToken = new TokenEntity();
        clientToken.setClientId(clientDetails.getClientId());
        clientToken.setCreatedAt(Instant.now());
        clientToken.setToken(tokenValue);
        clientToken.setRequesterId(requesterId);
        clientToken.setExpiredAt(Instant.now().plus(TOKEN_EXPIRY_IN_DAYS, ChronoUnit.DAYS));
        clientToken.setType(clientDetails.getType());

        tokenRepository.save(clientToken);
        log.info("Token stored successfully for clientId={}", clientDetails.getClientId());

        Token responseToken = new Token();
        responseToken.setToken(tokenValue);
        return responseToken;
    }

    /**
     * Validate token and refresh if expired or near expiry.
     * Allows optional post-refresh callback (e.g., to save token in custom storage).
     */
    @Transactional(propagation = Propagation.REQUIRED)
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
        Instant expiryTime = tokenEntity.getExpiredAt();
        long hoursUntilExpiry = Duration.between(now, expiryTime).toHours();

        // If token expired or near expiry, generate new one
        if (expiryTime.isBefore(now) || hoursUntilExpiry < 24) {
            log.info("Token expired or near expiry, generating a new one");
            Token refreshedToken = generateToken(request.getClientDetails());
            if (refreshedToken != null) {
                request.setToken(refreshedToken.getToken()); // update the same request
            }
        }

        return request.getToken();
    }


    /**
     * Find a token, regenerate if expired and URI matches.
     */
    public Optional<TokenEntity> findByToken(String token, String uri) {
        log.info("Finding token={}, uri={}", token, uri);

        Optional<TokenEntity> tokenEntityOpt = tokenRepository.findByToken(token);
        if (tokenEntityOpt.isPresent() && tokenEntityOpt.get().getExpiredAt().isAfter(Instant.now())) {
            return tokenEntityOpt;
        }

        if (uri.contains("/validate-app-token")) {
            log.info("Token expired, regenerating for /validate-app-token");
            ClientDetails clientDetails = new ClientDetails();
            clientDetails.setClientSecret(secretKey);
            clientDetails.setClientId(clientId);
            Token newToken = generateToken(clientDetails);
            if (newToken != null) {
                return tokenRepository.findByToken(newToken.getToken());
            }
        }

        return Optional.empty();
    }
}
