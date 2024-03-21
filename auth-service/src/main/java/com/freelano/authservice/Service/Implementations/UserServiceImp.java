package com.freelano.authservice.Service.Implementations;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Dto.Response.LoginResponse;
import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Entity.Roles;
import com.freelano.authservice.Repository.UserRepository;
import com.freelano.authservice.Service.Services.UserService;
import com.freelano.authservice.Util.JwtUtil.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
public class UserServiceImp implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Autowired
    public UserServiceImp(UserRepository userRepository, JwtService jwtService, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ResponseEntity<LoginResponse> login(LoginDto loginCredentials, HttpServletResponse response) {
        String email = loginCredentials.getEmail();
        String password = loginCredentials.getPassword();

        // Check if email already exist or not
        if (!isEmailExist(email)) {
            return ResponseEntity.ok(LoginResponse
                    .builder()
                    .message("Email not found. Would you like to create an account?")
                    .accessToken("")
                    .build());
        }
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            // if authenticated then generate token
            final String jwtToken = jwtService.generateToken(email);
            String encodedToken = Base64.getEncoder().encodeToString(jwtToken.getBytes());

            //Create a Cookie with 'accessToken' and HttpOnly, Expire, Secure.
            Cookie cookie = new Cookie("AccessToken",encodedToken);
            cookie.setMaxAge(60 * 60 * 24 * 2);  // 2 days
            cookie.setPath("/");
            cookie.setHttpOnly(false);
            cookie.setSecure(false);

            // add the cookie to response and return a LoginResponse Obj
            response.addCookie(cookie);
            return ResponseEntity.ok(LoginResponse
                    .builder()
                    .message("Successfully Logged In")
                    .accessToken(jwtToken)
                    .build());
        } catch (AuthenticationException e) {
            log.info("an error @loin" + e.getMessage());
            // if authentication fails during " new UsernamePasswordAuthenticationToken(email, password)" error will catch here
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(LoginResponse.builder()
                            .message("Invalid email or password.")
                            .accessToken("")
                            .build());
        } catch (Exception e) {
            log.error("An error occurred during login:", e);
            // if any other exception occurred catch here
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(LoginResponse.builder()
                            .message("An internal server error occurred.")
                            .accessToken("")
                            .build());
        }
    }

    @Override
    @Transactional
    public ResponseEntity<?> registerUser(RegisterDto userInfo) {
        if (isEmailExist(userInfo.getEmail())) {
            return new ResponseEntity<>("Email Already Exist", HttpStatus.BAD_REQUEST);
        }

        AuthEntity newUser = new AuthEntity();
        newUser.setUserId(UUID.randomUUID());
        newUser.setUserName(userInfo.getUserName());
        newUser.setEmail(userInfo.getEmail());
        newUser.setPassword(hashPassword(userInfo.getPassword()));

        String role = userInfo.getRole();
        if (isValidRole(role)) {
            switch (role) {
                case "CLIENT":
                    newUser.setRole(Roles.CLIENT);
                    break;
                case "FREELANCER":
                    newUser.setRole(Roles.FREELANCER);
                    break;
                case "ADMIN":
                    newUser.setRole(Roles.ADMIN);
                    break;
            }
        } else {
            return new ResponseEntity<>("Invalid Role", HttpStatus.BAD_REQUEST);
        }
        try {
            userRepository.save(newUser);
            return new ResponseEntity<>(newUser, HttpStatus.CREATED);
        } catch (Exception e) {
            log.info("registerUser @userServiceImp " + e.getMessage());
            return new ResponseEntity<>("Error occurred while saving user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }

    @Override
    public Boolean isEmailExist(String email) {
        return userRepository.existsByEmail(email);
    }

    private boolean isValidRole(String role) {
        return role != null && (role.equals("CLIENT") || role.equals("FREELANCER") || role.equals("ADMIN"));
    }

}
