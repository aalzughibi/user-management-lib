package com.aiops.usermanagement.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", 
    uniqueConstraints = {
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = "phone")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank
    @Size(max = 100)
    private String fullName;
    
    @NotBlank
    @Size(max = 100)
    @Email
    private String email;
    
    @Size(max = 20)
    @Pattern(regexp = "^[+]?[0-9]{10,15}$")
    private String phone;
    
    @NotBlank
    @Size(max = 120)
    @JsonIgnore
    private String password;
    
    @Enumerated(EnumType.STRING)
    private Gender gender;
    
    private LocalDate birthdate;
    
    @Size(max = 255)
    private String address;
    
    @Size(max = 255)
    private String profilePhotoUrl;
    
    @Column(nullable = false)
    private boolean emailVerified = false;
    
    @Column(nullable = false)
    private boolean phoneVerified = false;
    
    @Column(nullable = false)
    private boolean enabled = true;
    
    private boolean twoFactorEnabled = false;
    
    @Enumerated(EnumType.STRING)
    private TwoFactorType twoFactorType;
    
    @Size(max = 100)
    private String twoFactorSecret;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    @CreationTimestamp
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    
    private LocalDateTime lastLoginAt;
    
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;
    
    // Helper methods
    public boolean hasRole(String roleName) {
        return roles.stream().anyMatch(role -> role.getName().equals(roleName));
    }
    
    public enum Gender {
        MALE, FEMALE, OTHER, PREFER_NOT_TO_SAY
    }
    
    public enum UserStatus {
        ACTIVE, INACTIVE, LOCKED, DELETED
    }
    
    public enum TwoFactorType {
        SMS, EMAIL, AUTHENTICATOR_APP
    }
} 