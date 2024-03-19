package com.freelano.authservice.Service.Implementations;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Entity.Roles;
import com.freelano.authservice.Repository.UserRepository;
import com.freelano.authservice.Service.Services.UserService;
import com.freelano.authservice.Util.JwtUtil.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
    public ResponseEntity<String> login(LoginDto loginCredentials) {

        if (!isEmailExist(loginCredentials.getEmail())) {
            return new ResponseEntity<>("Email Not Exist", HttpStatus.BAD_REQUEST);
        }
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginCredentials.getEmail(), loginCredentials.getPassword()));
            final String jwtToken = "Bearer " + jwtService.generateToken(loginCredentials.getEmail());

            return new ResponseEntity<>(jwtToken, HttpStatus.OK);
        } catch (Exception exception) {
            log.info("UserServiceImpl login..");
            return new ResponseEntity<>("Invalid Credential", HttpStatus.UNAUTHORIZED);
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
            log.info("registerUser @userServiceImp "+e.getMessage());
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
