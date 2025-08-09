package com.neoteric.dpop.core.token.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "avoota_client_details", schema = "avoota")
public class ClientDetailsEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "secret_key")
    private String secretKey;

    @Column(name = "type")
    private String type;

}
