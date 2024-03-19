package com.freelano.authservice.Controller;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Service.Services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    private final UserService clientService;
    @Autowired
    public AuthController(UserService clientService) {
        this.clientService = clientService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginDto loginCredentials){

        return clientService.login(loginCredentials);
    }

    @GetMapping("/check")
    public ResponseEntity<String> checkService(){
        return ResponseEntity.ok("Connection Successfully Established");
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterDto registerDetails){
        return clientService.registerUser(registerDetails);
    }
}
