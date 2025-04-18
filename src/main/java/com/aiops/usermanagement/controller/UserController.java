package com.aiops.usermanagement.controller;

import com.aiops.usermanagement.dto.request.PasswordChangeRequest;
import com.aiops.usermanagement.dto.request.ProfileUpdateRequest;
import com.aiops.usermanagement.dto.response.ApiResponse;
import com.aiops.usermanagement.dto.response.UserDTO;
import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/users/me")
    public ResponseEntity<UserDTO> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUser());
    }
    
    @PutMapping("/users/me")
    public ResponseEntity<UserDTO> updateProfile(@Valid @RequestBody ProfileUpdateRequest profileUpdateRequest) {
        return ResponseEntity.ok(userService.updateProfile(profileUpdateRequest));
    }
    
    @PostMapping("/users/me/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@Valid @RequestBody PasswordChangeRequest passwordChangeRequest) {
        userService.changePassword(passwordChangeRequest);
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully."));
    }
    
    @PostMapping(value = "/users/me/photo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<Void>> updateProfilePhoto(@RequestParam("photo") MultipartFile photo) {
        userService.updateProfilePhoto(photo);
        return ResponseEntity.ok(ApiResponse.success("Profile photo updated successfully."));
    }
    
    @DeleteMapping("/users/me/photo")
    public ResponseEntity<ApiResponse<Void>> deleteProfilePhoto() {
        userService.deleteProfilePhoto();
        return ResponseEntity.ok(ApiResponse.success("Profile photo deleted successfully."));
    }
    
    @PostMapping("/users/2fa/enable")
    public ResponseEntity<ApiResponse<Void>> enableTwoFactorAuth(@RequestParam String type) {
        userService.enableTwoFactorAuth(type);
        return ResponseEntity.ok(ApiResponse.success("Two-factor authentication enabled successfully."));
    }
    
    @PostMapping("/users/2fa/disable")
    public ResponseEntity<ApiResponse<Void>> disableTwoFactorAuth() {
        userService.disableTwoFactorAuth();
        return ResponseEntity.ok(ApiResponse.success("Two-factor authentication disabled successfully."));
    }
    
    // Admin endpoints
    
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserDTO>> getAllUsers(@PageableDefault(size = 10) Pageable pageable) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }
    
    @GetMapping("/admin/users/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @RequestParam(required = false) String searchTerm,
            @RequestParam(required = false) User.UserStatus status,
            @PageableDefault(size = 10) Pageable pageable) {
        return ResponseEntity.ok(userService.searchUsers(searchTerm, status, pageable));
    }
    
    @GetMapping("/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }
    
    @PutMapping("/admin/users/{id}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> enableUser(@PathVariable Long id) {
        userService.enableUser(id);
        return ResponseEntity.ok(ApiResponse.success("User enabled successfully."));
    }
    
    @PutMapping("/admin/users/{id}/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> disableUser(@PathVariable Long id) {
        userService.disableUser(id);
        return ResponseEntity.ok(ApiResponse.success("User disabled successfully."));
    }
    
    @DeleteMapping("/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully."));
    }
    
    @PostMapping("/admin/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> assignRole(
            @PathVariable Long id, 
            @RequestParam String roleName) {
        userService.assignRole(id, roleName);
        return ResponseEntity.ok(ApiResponse.success("Role assigned successfully."));
    }
    
    @DeleteMapping("/admin/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> removeRole(
            @PathVariable Long id, 
            @RequestParam String roleName) {
        userService.removeRole(id, roleName);
        return ResponseEntity.ok(ApiResponse.success("Role removed successfully."));
    }
    
    @GetMapping("/admin/users/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<String>> getUserRoles(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserRoles(id));
    }
} 