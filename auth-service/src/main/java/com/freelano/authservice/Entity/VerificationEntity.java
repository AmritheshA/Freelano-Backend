package com.freelano.authservice.Entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "verificationTable")
@Getter
@Setter
public class VerificationEntity {

    @Id
    private UUID verificationId;
    private String email;
    private String token;

}
