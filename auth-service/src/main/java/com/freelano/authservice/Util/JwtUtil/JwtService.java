package com.freelano.authservice.Util.JwtUtil;



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

    @Value("${JWT_SECRET}")
    private String jwtSecret;

    private final UserRepository clientRepository;

    @Autowired
    public JwtService(UserRepository userRepository) {
        this.clientRepository = userRepository;
    }

    public String generateToken(String email) {
        Date currentDate = new Date();
        Date expirationTime = new Date(currentDate.getTime() + 30 * 24 * 60 * 60 * 1000L);
        AuthEntity user = clientRepository.findByEmail(email);
        System.out.println("{}"+user.getUserName());
        return Jwts.builder()
                .setSubject(email)
                .claim("userId",user.getUserId())
                .claim("userName", user.getUserName())
                .claim("role",user.getRole()).setExpiration(expirationTime)
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

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public String getJWTFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return " ";
    }

}