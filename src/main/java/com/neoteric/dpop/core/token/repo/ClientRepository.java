package com.neoteric.dpop.core.token.repo;


import com.neoteric.dpop.core.token.entity.ClientDetailsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<ClientDetailsEntity, Long> {
    Optional<ClientDetailsEntity> findByClientId(String clientId);
}
