package com.freelano.authservice.Service.UserDetailsService;


import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        if (!userRepository.existsByEmail(email))
            throw new UsernameNotFoundException("Email not found");
        log.info("email...");
        AuthEntity user = userRepository.findByEmail(email);
        return new CustomUserDetails(user);
    }
}