package com.freelano.authservice.Controller;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.OauthRequest;
import com.freelano.authservice.Dto.Request.RegisterDto;

import com.freelano.authservice.Dto.Response.LoginResponse;
import com.freelano.authservice.Service.Services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
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
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginDto loginCredentials, HttpServletResponse response){
        return clientService.login(loginCredentials,response);
    }

    @GetMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam("token") String token,HttpServletRequest request,HttpServletResponse response){
        System.out.println("Token from controller"+token);
        return clientService.registerUser(token,request,response);
    }

    @PostMapping("/oauth/login")
    public ResponseEntity<String> googleOauthLogin(@RequestBody OauthRequest oauthDetails,HttpServletResponse response){
        return clientService.googleOauth(oauthDetails,response);
    }

    @PostMapping("/sendMail")
    public ResponseEntity<?> verifyUserEmail(@RequestBody RegisterDto  registerDetails, HttpServletResponse response){
        return clientService.sendEmail(registerDetails,response);
    }

    @GetMapping("/check")
    public ResponseEntity<String> checkService(){
        return ResponseEntity.ok("Connection Successfully Established");
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue(name = "AccessToken", required = false) String authToken, HttpServletResponse response) {
        // Invalidate the authentication token
        SecurityContextHolder.clearContext();

        // Clear the token from the cookie
        if (authToken != null) {
            Cookie cookie = new Cookie("AccessToken", null);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(0);
            cookie.setPath("/");
            response.addCookie(cookie);
        }

        return ResponseEntity.ok("Logout successful");
    }
}
