package com.aiops.usermanagement.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_sessions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String token;
    
    @Column(name = "refresh_token")
    private String refreshToken;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    private LocalDateTime lastAccessedAt;
    
    @Column(length = 50)
    private String ipAddress;
    
    @Column(length = 255)
    private String userAgent;
    
    @Column(length = 255)
    private String deviceInfo;
    
    @Column(nullable = false)
    private boolean active = true;
    
    private LocalDateTime terminatedAt;
    
    @Enumerated(EnumType.STRING)
    private TerminationReason terminationReason;
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
    
    public enum TerminationReason {
        USER_LOGOUT,
        ADMIN_TERMINATION,
        SESSION_EXPIRED,
        SECURITY_VIOLATION
    }
} 