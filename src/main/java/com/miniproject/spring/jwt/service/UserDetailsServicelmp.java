package com.miniproject.spring.jwt.service;

import com.miniproject.spring.jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServicelmp implements UserDetailsService {

    private final UserRepository repository;

    public UserDetailsServicelmp(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username).
                orElseThrow(() -> new UsernameNotFoundException("User not found"));

    }
}
