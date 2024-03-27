package com.freelano.authservice.Dto.Request;

import lombok.Data;

@Data
public class SendMailDto {
    private String confirmPassword;
    private String email;
    private String password;
    private String userName;
}
