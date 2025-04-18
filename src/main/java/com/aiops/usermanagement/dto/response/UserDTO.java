package com.aiops.usermanagement.dto.response;

import com.aiops.usermanagement.entity.User.Gender;
import com.aiops.usermanagement.entity.User.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long id;
    private String fullName;
    private String email;
    private String phone;
    private Gender gender;
    private LocalDate birthdate;
    private String address;
    private String profilePhotoUrl;
    private boolean emailVerified;
    private boolean phoneVerified;
    private boolean enabled;
    private boolean twoFactorEnabled;
    private Set<String> roles;
    private UserStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
} 