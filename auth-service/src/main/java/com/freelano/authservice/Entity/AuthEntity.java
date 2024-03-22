package com.freelano.authservice.Entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "AuthEntity")
@Getter
@Setter
public class AuthEntity {

    @Id
    private UUID userId;

    @NotBlank(message = "Username cannot be blank")
    @NotNull(message = "Username cannot be null")
    private String userName;

    @Email(message = "Invalid email format")
    @NotNull(message = "Email cannot be null")
    private String email;

    @NotBlank(message = "Password cannot be blank")
    @NotNull(message = "Password cannot be null")
    @JsonIgnore
    private String password;

    @NotNull(message = "Role cannot be null")
    @Enumerated(EnumType.STRING)
    private Roles role;

    @Temporal(TemporalType.DATE)
    private Date lastPasswordUpdated;


    public void setPassword(String password) {
        this.password = password;
        this.lastPasswordUpdated = new Date();
    }
}
