package com.freelano.authservice.Service.Services;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.RegisterDto;
import org.springframework.http.ResponseEntity;


public interface UserService {
    ResponseEntity<String> login(LoginDto loginCredentials);
    Boolean isEmailExist(String email);
    ResponseEntity<?> registerUser(RegisterDto registerDetails);

}
