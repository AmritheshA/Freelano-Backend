package com.freelano.authservice.Dto.Request;


import lombok.Data;

@Data
public class OauthRequest {

    private String oauthToken;
    private String role;

}
