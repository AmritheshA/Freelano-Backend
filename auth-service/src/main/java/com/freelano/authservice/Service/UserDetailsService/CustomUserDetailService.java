package com.freelano.authservice.Service.UserDetailsService;


import com.freelano.authservice.Entity.AuthEntity;
import com.freelano.authservice.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        if (!userRepository.existsByEmail(email))
            throw new UsernameNotFoundException("Username not found");
        AuthEntity user = userRepository.findByEmail(email);
        return new CustomUserDetails(user);
    }
}