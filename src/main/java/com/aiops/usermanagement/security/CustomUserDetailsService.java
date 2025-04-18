package com.aiops.usermanagement.security;

import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.exception.ResourceNotFoundException;
import com.aiops.usermanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmailOrPhone) throws UsernameNotFoundException {
        // Try to load by email
        User user = userRepository.findByEmail(usernameOrEmailOrPhone)
                .orElse(null);
        
        // If not found, try by phone
        if (user == null) {
            user = userRepository.findByPhone(usernameOrEmailOrPhone)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username, email or phone: " + usernameOrEmailOrPhone));
        }
        
        return UserPrincipal.create(user);
    }

    @Transactional
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        return UserPrincipal.create(user);
    }
} 