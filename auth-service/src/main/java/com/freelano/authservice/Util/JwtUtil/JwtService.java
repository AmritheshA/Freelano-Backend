package com.freelano.authservice.Util.JwtUtil;


import com.freelano.authservice.Dto.Request.RegisterDto;
import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Date;

@Service
public class JwtService {

    private final UserRepository clientRepository;
    @Value("${JWT_SECRET}")
    private String jwtSecret;

    @Autowired
    public JwtService(UserRepository userRepository) {
        this.clientRepository = userRepository;
    }

    public String generateToken(String email) {
        Date currentDate = new Date();
        Date expirationTime = new Date(currentDate.getTime() + 30 * 24 * 60 * 60 * 1000L);
        AuthEntity user = clientRepository.findByEmail(email);
        System.out.println("{}" + user.getUserName());
        return Jwts.builder()
                .setSubject(email)
                .claim("userId", user.getUserId())
                .claim("userName", user.getUserName())
                .claim("role", user.getRole()).setExpiration(expirationTime)
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    public String generateUserDetailsToken(RegisterDto userDetails) {
        Date currentDate = new Date();
        Date expirationTime = new Date(currentDate.getTime() + 30 * 24 * 60 * 60 * 1000L);
        return Jwts.builder()
                .setSubject(userDetails.getEmail())
                .claim("username", userDetails.getUserName())
                .claim("password",userDetails.getPassword())
                .claim("role", userDetails.getRole())
                .setExpiration(expirationTime)
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }


    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            throw new AuthenticationCredentialsNotFoundException("Jwt token is expired or is invalid");
        }
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
    }


    public RegisterDto getUserDetailsFromToken(String userToken) {
        System.out.println("Attempting to extract user details from token..."+userToken);
        Claims claims = extractClaims(userToken);
        if (claims != null) {
            try {
                String username = claims.get("username", String.class);
                String email = claims.getSubject();
                String password = claims.get("password", String.class);
                String role = claims.get("role", String.class);

                System.out.println(username + " " + email + " " + password);
                if (username != null && email != null && password != null && role != null) {
                    return RegisterDto.builder()
                            .userName(username)
                            .email(email)
                            .password(password)
                            .role(role)
                            .build();
                } else {
                    System.err.println("Missing required claims in the token.");
                }
            } catch (Exception e) {
                // Handle errors when retrieving specific claims
                e.getMessage();
                throw new RuntimeException();
            }
        } else {
            System.err.println("Unable to extract claims from the token.");
        }
        return null;
    }
    public String getJWTFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return " ";
    }

}