package com.freelano.authservice.Service.Services;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.OauthRequest;
import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Dto.Response.LoginResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.actuate.autoconfigure.observation.ObservationProperties;
import org.springframework.http.ResponseEntity;


public interface UserService {
    ResponseEntity<LoginResponse> login(LoginDto loginCredentials, HttpServletResponse response);
    Boolean isEmailExist(String email);
    ResponseEntity<?> registerUser(RegisterDto registerDetails,HttpServletResponse response);
    ResponseEntity<String> googleOauth(OauthRequest oauthDetails, HttpServletResponse response);
}
