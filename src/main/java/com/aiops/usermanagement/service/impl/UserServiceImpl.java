package com.aiops.usermanagement.service.impl;

import com.aiops.usermanagement.dto.request.PasswordChangeRequest;
import com.aiops.usermanagement.dto.request.ProfileUpdateRequest;
import com.aiops.usermanagement.dto.response.UserDTO;
import com.aiops.usermanagement.entity.AuditLog.ActionType;
import com.aiops.usermanagement.entity.Role;
import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.User.TwoFactorType;
import com.aiops.usermanagement.entity.User.UserStatus;
import com.aiops.usermanagement.exception.BadRequestException;
import com.aiops.usermanagement.exception.ResourceNotFoundException;
import com.aiops.usermanagement.repository.RoleRepository;
import com.aiops.usermanagement.repository.UserRepository;
import com.aiops.usermanagement.repository.UserSessionRepository;
import com.aiops.usermanagement.security.UserPrincipal;
import com.aiops.usermanagement.service.AuditService;
import com.aiops.usermanagement.service.EmailService;
import com.aiops.usermanagement.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final EmailService emailService;
    
    private static final String UPLOAD_DIR = "uploads/profile-photos";

    @Override
    public UserDTO getCurrentUser() {
        User user = getAuthenticatedUser();
        return mapUserToDTO(user);
    }

    @Override
    public UserDTO getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
        return mapUserToDTO(user);
    }

    @Override
    @Transactional
    public UserDTO updateProfile(ProfileUpdateRequest profileUpdateRequest) {
        User user = getAuthenticatedUser();
        
        if (profileUpdateRequest.getFullName() != null && !profileUpdateRequest.getFullName().isEmpty()) {
            user.setFullName(profileUpdateRequest.getFullName());
        }
        
        if (profileUpdateRequest.getPhone() != null && !profileUpdateRequest.getPhone().isEmpty()) {
            // Reset phone verification if phone number changes
            if (!profileUpdateRequest.getPhone().equals(user.getPhone())) {
                user.setPhoneVerified(false);
            }
            user.setPhone(profileUpdateRequest.getPhone());
        }
        
        if (profileUpdateRequest.getGender() != null) {
            user.setGender(profileUpdateRequest.getGender());
        }
        
        if (profileUpdateRequest.getBirthdate() != null) {
            user.setBirthdate(profileUpdateRequest.getBirthdate());
        }
        
        if (profileUpdateRequest.getAddress() != null) {
            user.setAddress(profileUpdateRequest.getAddress());
        }
        
        userRepository.save(user);
        
        auditService.logUserAction(user, ActionType.PROFILE_UPDATE, 
                "User profile updated", null);
        
        return mapUserToDTO(user);
    }

    @Override
    @Transactional
    public void changePassword(PasswordChangeRequest passwordChangeRequest) {
        User user = getAuthenticatedUser();
        
        // Verify current password
        if (!passwordEncoder.matches(passwordChangeRequest.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }
        
        // Verify passwords match
        if (!passwordChangeRequest.getNewPassword().equals(passwordChangeRequest.getConfirmPassword())) {
            throw new BadRequestException("New passwords do not match");
        }
        
        // Set new password
        user.setPassword(passwordEncoder.encode(passwordChangeRequest.getNewPassword()));
        userRepository.save(user);
        
        auditService.logUserAction(user, ActionType.PASSWORD_CHANGE, 
                "Password changed", null);
    }

    @Override
    @Transactional
    public void updateProfilePhoto(MultipartFile photo) {
        User user = getAuthenticatedUser();
        
        if (photo.isEmpty()) {
            throw new BadRequestException("Please select a file to upload");
        }
        
        try {
            // Create upload directory if it doesn't exist
            Path uploadPath = Paths.get(UPLOAD_DIR);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }
            
            // Generate unique filename
            String filename = user.getId() + "_" + UUID.randomUUID() + "_" + photo.getOriginalFilename();
            Path filePath = uploadPath.resolve(filename);
            
            // Save the file
            Files.copy(photo.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
            
            // Update user profile photo URL
            user.setProfilePhotoUrl(UPLOAD_DIR + "/" + filename);
            userRepository.save(user);
            
            auditService.logUserAction(user, ActionType.PROFILE_UPDATE, 
                    "Profile photo updated", null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to store file", e);
        }
    }

    @Override
    @Transactional
    public void deleteProfilePhoto() {
        User user = getAuthenticatedUser();
        
        if (user.getProfilePhotoUrl() != null) {
            try {
                // Delete file from filesystem
                Path photoPath = Paths.get(user.getProfilePhotoUrl());
                Files.deleteIfExists(photoPath);
            } catch (IOException e) {
                throw new RuntimeException("Failed to delete file", e);
            }
            
            // Update user profile
            user.setProfilePhotoUrl(null);
            userRepository.save(user);
            
            auditService.logUserAction(user, ActionType.PROFILE_UPDATE, 
                    "Profile photo deleted", null);
        }
    }

    @Override
    public Page<UserDTO> getAllUsers(Pageable pageable) {
        Page<User> users = userRepository.findAll(pageable);
        return users.map(this::mapUserToDTO);
    }

    @Override
    public Page<UserDTO> searchUsers(String searchTerm, UserStatus status, Pageable pageable) {
        String term = (searchTerm == null) ? "" : searchTerm;
        Page<User> users = userRepository.searchUsers(term, status, pageable);
        return users.map(this::mapUserToDTO);
    }

    @Override
    @Transactional
    public void enableUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        user.setEnabled(true);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);
        
        emailService.sendAccountUnlockedEmail(user);
        
        auditService.logUserAction(user, ActionType.ACCOUNT_ENABLED, 
                "User account enabled by admin", null);
    }

    @Override
    @Transactional
    public void disableUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        // Prevent self-lockout
        User currentUser = getAuthenticatedUser();
        if (userId.equals(currentUser.getId())) {
            throw new BadRequestException("You cannot disable your own account");
        }
        
        user.setEnabled(false);
        user.setStatus(UserStatus.INACTIVE);
        userRepository.save(user);
        
        // Invalidate all active sessions
        sessionRepository.deactivateAllUserSessions(
                user, 
                LocalDateTime.now(), 
                com.aiops.usermanagement.entity.UserSession.TerminationReason.ADMIN_TERMINATION);
        
        emailService.sendAccountLockedEmail(user);
        
        auditService.logUserAction(user, ActionType.ACCOUNT_DISABLED, 
                "User account disabled by admin", null);
    }

    @Override
    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        // Prevent self-deletion
        User currentUser = getAuthenticatedUser();
        if (userId.equals(currentUser.getId())) {
            throw new BadRequestException("You cannot delete your own account");
        }
        
        // Soft delete - We keep the record but mark it as deleted
        user.setStatus(UserStatus.DELETED);
        user.setEnabled(false);
        userRepository.save(user);
        
        // Invalidate all active sessions
        sessionRepository.deactivateAllUserSessions(
                user, 
                LocalDateTime.now(), 
                com.aiops.usermanagement.entity.UserSession.TerminationReason.ADMIN_TERMINATION);
        
        auditService.logUserAction(user, ActionType.ADMIN_ACTION, 
                "User account deleted by admin", null);
    }

    @Override
    @Transactional
    public void assignRole(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        // Convert role name to enum format if needed
        final String finalRoleName;
        if (!roleName.startsWith("ROLE_")) {
            finalRoleName = "ROLE_" + roleName.toUpperCase();
        } else {
            finalRoleName = roleName;
        }
        
        try {
            Role.ERole eRole = Role.ERole.valueOf(finalRoleName);
            Role role = roleRepository.findByName(eRole)
                    .orElseThrow(() -> new ResourceNotFoundException("Role", "name", finalRoleName));
            
            if (!user.getRoles().contains(role)) {
                user.getRoles().add(role);
                userRepository.save(user);
                
                emailService.sendRoleChangedEmail(user, eRole.name());
                
                auditService.logUserAction(user, ActionType.ROLE_CHANGE, 
                        "Role " + eRole.name() + " assigned to user", null);
            }
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid role name: " + finalRoleName);
        }
    }

    @Override
    @Transactional
    public void removeRole(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        // Convert role name to enum format if needed
        final String finalRoleName;
        if (!roleName.startsWith("ROLE_")) {
            finalRoleName = "ROLE_" + roleName.toUpperCase();
        } else {
            finalRoleName = roleName;
        }
        
        try {
            Role.ERole eRole = Role.ERole.valueOf(finalRoleName);
            Role role = roleRepository.findByName(eRole)
                    .orElseThrow(() -> new ResourceNotFoundException("Role", "name", finalRoleName));
            
            // Prevent removing the last role
            if (user.getRoles().size() <= 1) {
                throw new BadRequestException("Cannot remove the last role from user");
            }
            
            if (user.getRoles().contains(role)) {
                user.getRoles().remove(role);
                userRepository.save(user);
                
                auditService.logUserAction(user, ActionType.ROLE_CHANGE, 
                        "Role " + eRole.name() + " removed from user", null);
            }
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid role name: " + finalRoleName);
        }
    }

    @Override
    @Transactional
    public void enableTwoFactorAuth(String type) {
        User user = getAuthenticatedUser();
        
        TwoFactorType twoFactorType;
        try {
            twoFactorType = TwoFactorType.valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid two-factor authentication type");
        }
        
        // In a real app, we would generate and store a secret key
        // For demo purposes, we just enable it
        user.setTwoFactorEnabled(true);
        user.setTwoFactorType(twoFactorType);
        user.setTwoFactorSecret("DEMO_SECRET_KEY"); // This would be a real secret key in production
        userRepository.save(user);
        
        auditService.logUserAction(user, ActionType.TWO_FACTOR_ENABLED, 
                "Two-factor authentication enabled", null);
    }

    @Override
    @Transactional
    public void disableTwoFactorAuth() {
        User user = getAuthenticatedUser();
        
        user.setTwoFactorEnabled(false);
        user.setTwoFactorType(null);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
        
        auditService.logUserAction(user, ActionType.TWO_FACTOR_DISABLED, 
                "Two-factor authentication disabled", null);
    }

    @Override
    public List<String> getUserRoles(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        
        return user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());
    }
    
    // Helper methods
    
    private User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
    
    private UserDTO mapUserToDTO(User user) {
        Set<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet());
        
        return UserDTO.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .phone(user.getPhone())
                .gender(user.getGender())
                .birthdate(user.getBirthdate())
                .address(user.getAddress())
                .profilePhotoUrl(user.getProfilePhotoUrl())
                .emailVerified(user.isEmailVerified())
                .phoneVerified(user.isPhoneVerified())
                .enabled(user.isEnabled())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .roles(roles)
                .status(user.getStatus())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }
} 