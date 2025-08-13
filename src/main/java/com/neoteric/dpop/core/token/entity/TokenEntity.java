package com.neoteric.dpop.core.token.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "app_tokens", schema = "avoota")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "token")
    private String token;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "type", updatable = false)
    private String type;

    @Column(name = "expired_at", updatable = false)
    private Instant expiredAt;

    @Column(name = "requester_id", updatable = false)
    private String requesterId;
    @Lob
    @Column(name = "public_key_jwk")
    private String publicKeyJwk;

}

