package com.aiops.usermanagement.service;

import com.aiops.usermanagement.dto.request.PasswordChangeRequest;
import com.aiops.usermanagement.dto.request.ProfileUpdateRequest;
import com.aiops.usermanagement.dto.response.UserDTO;
import com.aiops.usermanagement.entity.User.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserService {
    UserDTO getCurrentUser();
    
    UserDTO getUserById(Long id);
    
    UserDTO updateProfile(ProfileUpdateRequest profileUpdateRequest);
    
    void changePassword(PasswordChangeRequest passwordChangeRequest);
    
    void updateProfilePhoto(MultipartFile photo);
    
    void deleteProfilePhoto();
    
    Page<UserDTO> getAllUsers(Pageable pageable);
    
    Page<UserDTO> searchUsers(String searchTerm, UserStatus status, Pageable pageable);
    
    void enableUser(Long userId);
    
    void disableUser(Long userId);
    
    void deleteUser(Long userId);
    
    void assignRole(Long userId, String roleName);
    
    void removeRole(Long userId, String roleName);
    
    void enableTwoFactorAuth(String type);
    
    void disableTwoFactorAuth();
    
    List<String> getUserRoles(Long userId);
} 