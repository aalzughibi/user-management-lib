package com.aiops.usermanagement.config;

import com.aiops.usermanagement.entity.Permission;
import com.aiops.usermanagement.entity.Role;
import com.aiops.usermanagement.entity.Role.ERole;
import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.User.UserStatus;
import com.aiops.usermanagement.repository.PermissionRepository;
import com.aiops.usermanagement.repository.RoleRepository;
import com.aiops.usermanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class DatabaseSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        log.info("Initializing database with default roles and permissions...");
        
        // Create default permissions
        createDefaultPermissions();
        
        // Create default roles
        createDefaultRoles();
        
        // Create default admin user if not exists
        createDefaultAdminUser();
        
        log.info("Database initialization completed.");
    }
    
    private void createDefaultPermissions() {
        List<String> defaultPermissions = Arrays.asList(
                "user:read", "user:write", "user:delete",
                "role:read", "role:write", "role:delete",
                "profile:read", "profile:write"
        );
        
        for (String permName : defaultPermissions) {
            if (!permissionRepository.existsByName(permName)) {
                Permission permission = Permission.builder()
                        .name(permName)
                        .description("Permission to " + permName.replace(":", " "))
                        .build();
                permissionRepository.save(permission);
                log.info("Created permission: {}", permName);
            }
        }
    }
    
    private void createDefaultRoles() {
        // User role
        if (roleRepository.findByName(ERole.ROLE_USER).isEmpty()) {
            Role userRole = Role.builder()
                    .name(ERole.ROLE_USER)
                    .description("Regular user with basic permissions")
                    .permissions(new HashSet<>(permissionRepository.findAllById(Arrays.asList(7L, 8L)))) // profile permissions
                    .build();
            roleRepository.save(userRole);
            log.info("Created role: {}", ERole.ROLE_USER);
        }
        
        // Moderator role
        if (roleRepository.findByName(ERole.ROLE_MODERATOR).isEmpty()) {
            Role modRole = Role.builder()
                    .name(ERole.ROLE_MODERATOR)
                    .description("Moderator with user management permissions")
                    .permissions(new HashSet<>(permissionRepository.findAllById(Arrays.asList(1L, 4L, 7L, 8L)))) // user read, role read, profile permissions
                    .build();
            roleRepository.save(modRole);
            log.info("Created role: {}", ERole.ROLE_MODERATOR);
        }
        
        // Admin role
        if (roleRepository.findByName(ERole.ROLE_ADMIN).isEmpty()) {
            Set<Permission> allPermissions = new HashSet<>(permissionRepository.findAll());
            Role adminRole = Role.builder()
                    .name(ERole.ROLE_ADMIN)
                    .description("Administrator with all permissions")
                    .permissions(allPermissions)
                    .build();
            roleRepository.save(adminRole);
            log.info("Created role: {}", ERole.ROLE_ADMIN);
        }
    }
    
    private void createDefaultAdminUser() {
        if (userRepository.findByEmail("admin@example.com").isEmpty()) {
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Admin role not found. Database initialization failed."));
            
            User adminUser = User.builder()
                    .fullName("System Administrator")
                    .email("admin@example.com")
                    .password(passwordEncoder.encode("Admin@123"))
                    .enabled(true)
                    .emailVerified(true)
                    .status(UserStatus.ACTIVE)
                    .roles(new HashSet<>(Arrays.asList(adminRole)))
                    .build();
            
            userRepository.save(adminUser);
            log.info("Created default admin user: {}", adminUser.getEmail());
        }
    }
} 