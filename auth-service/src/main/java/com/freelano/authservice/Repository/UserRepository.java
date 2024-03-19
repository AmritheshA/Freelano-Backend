package com.freelano.authservice.Repository;

import com.freelano.authservice.Entity.AuthEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<AuthEntity, UUID> {

    AuthEntity findByEmail(String email);

    Boolean existsByEmail(String email);

}
