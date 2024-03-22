package com.freelano.authservice.Service.Implementations;

import com.freelano.authservice.Dto.Request.LoginDto;
import com.freelano.authservice.Dto.Request.OauthRequest;
import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Dto.Response.LoginResponse;
import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Entity.Roles;
import com.freelano.authservice.Repository.UserRepository;
import com.freelano.authservice.Service.Services.UserService;
import com.freelano.authservice.Service.UserDetailsService.CustomUserDetailService;
import com.freelano.authservice.Util.JwtUtil.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
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
    private final CustomUserDetailService customUserDetailService;

    @Autowired
    public UserServiceImp(UserRepository userRepository, JwtService jwtService, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, CustomUserDetailService customUserDetailService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.customUserDetailService = customUserDetailService;
    }

    @Override
    public ResponseEntity<LoginResponse> login(LoginDto loginCredentials, HttpServletResponse response) {
        String email = loginCredentials.getEmail();
        String password = loginCredentials.getPassword();

        // Check if email already exist or not
        if (!isEmailExist(email)) {
            return ResponseEntity.ok(LoginResponse.builder().message("Email not found. Would you like to create an account?").accessToken("").build());
        }
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            // if authenticated then generate token and add it to response
            final String jwtToken = jwtService.generateToken(email);
            Cookie cookie = getCookieWithToken(jwtToken);
            response.addCookie(cookie);
            return ResponseEntity.ok(LoginResponse.builder().message("Successfully Logged In").accessToken(jwtToken).build());
        } catch (AuthenticationException e) {
            log.info("an error @loin" + e.getMessage());
            // if authentication fails during " new UsernamePasswordAuthenticationToken(email, password)" error will catch here
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(LoginResponse.builder().message("Invalid email or password.").accessToken("").build());
        } catch (Exception e) {
            log.error("An error occurred during login:", e);
            // if any other exception occurred catch here
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(LoginResponse.builder().message("An internal server error occurred.").accessToken("").build());
        }
    }

    @Override
    @Transactional
    public ResponseEntity<?> registerUser(RegisterDto userInfo, HttpServletResponse response) {
        // Check if your is registered with email
        if (isEmailExist(userInfo.getEmail())) {
            return new ResponseEntity<>("Email Already Exist", HttpStatus.BAD_REQUEST);
        }
        // Map DTO into AuthEntity
        AuthEntity newUser = new AuthEntity();
        newUser.setUserId(UUID.randomUUID());
        newUser.setUserName(userInfo.getUserName());
        newUser.setEmail(userInfo.getEmail());
        newUser.setPassword(hashPassword(userInfo.getPassword()));
        newUser.setRole(getRole(userInfo.getRole()));

        try {
            // Save the user and authenticate
            AuthEntity savedUser = userRepository.save(newUser);
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(savedUser.getEmail(), userInfo.getPassword()));

            // Generate JWT token set it into response
            final String jwtToken = jwtService.generateToken(savedUser.getEmail());
            Cookie cookie = getCookieWithToken(jwtToken);
            response.addCookie(cookie);

            return new ResponseEntity<>(newUser, HttpStatus.CREATED);
        } catch (Exception e) {
            log.info("registerUser @userServiceImp " + e.getMessage());
            return new ResponseEntity<>("Error occurred while saving user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> googleOauth(OauthRequest oauthDetails, HttpServletResponse response) {
        // Extract userDetails from token
        String[] chunks = oauthDetails.getOauthToken().split("\\.");
        String payload = new String(Base64.getDecoder().decode(chunks[1]));
        JSONObject payloadJson = new JSONObject(payload);
        String email = payloadJson.getString("email");
        String name = payloadJson.getString("name");
        log.info("before");
        // Check if the user is registered or not if no register him.
        if (!isEmailExist(email)) {
            log.info("newUser");
            registerOauthUser(email, name, oauthDetails.getRole());
        }
        log.info("after");
        try {
            // Authenticate user and generate token and add to response
            UserDetails userDetails = customUserDetailService.loadUserByUsername(email);
            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            String token = jwtService.generateToken(email);
            Cookie cookie = getCookieWithToken(token);
            response.addCookie(cookie);
            return new ResponseEntity<>(token, HttpStatus.OK);

        }catch (AuthenticationException e){
            log.info(e.getMessage());
            return new ResponseEntity<>("Something Went Wrong",HttpStatus.UNAUTHORIZED);
        }
    }

    protected void registerOauthUser(String email, String name, String role) {
        try {
            log.info("newUser");
            AuthEntity newUser = new AuthEntity();
            newUser.setUserId(UUID.randomUUID());
            newUser.setUserName(name);
            newUser.setEmail(email);
            newUser.setPassword(hashPassword(UUID.randomUUID().toString()));
            newUser.setRole(getRole(role));
            userRepository.save(newUser);
            log.info("user Saved");
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new RuntimeException("registerOauthUser" + e.getMessage());
        }
    }

    private Cookie getCookieWithToken(String jwtToken) {
        String encodedToken = Base64.getEncoder().encodeToString(jwtToken.getBytes());
        //Create a Cookie with 'accessToken' and HttpOnly, Expire, Secure.
        Cookie cookie = new Cookie("AccessToken", encodedToken);
        cookie.setMaxAge(60 * 60 * 24 * 2);  // 2 days
        cookie.setPath("/");
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        return cookie;
    }

    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }

    private Roles getRole(String role) {
        return switch (role) {
            case "ADMIN" -> Roles.ADMIN;
            case "FREELANCER" -> Roles.FREELANCER;
            default -> Roles.CLIENT;
        };
    }

    @Override
    public Boolean isEmailExist(String email) {
        return userRepository.existsByEmail(email);
    }


}
