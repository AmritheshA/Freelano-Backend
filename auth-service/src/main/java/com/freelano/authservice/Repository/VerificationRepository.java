package com.freelano.authservice.Repository;

import com.freelano.authservice.Entity.VerificationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface VerificationRepository extends JpaRepository<VerificationEntity , UUID> {

    VerificationEntity findByEmail(String email);

    boolean existsByEmail(String email);

}
