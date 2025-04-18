package com.aiops.usermanagement.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ActionType actionType;
    
    @Column(length = 255)
    private String description;
    
    @Column(length = 50)
    private String ipAddress;
    
    @Column(length = 255)
    private String userAgent;
    
    @CreationTimestamp
    private LocalDateTime timestamp;
    
    @Column(length = 500)
    private String details;
    
    public enum ActionType {
        LOGIN_SUCCESS,
        LOGIN_FAILED,
        LOGOUT,
        PROFILE_UPDATE,
        PASSWORD_CHANGE,
        PASSWORD_RESET,
        REGISTRATION,
        EMAIL_VERIFICATION,
        PHONE_VERIFICATION,
        ROLE_CHANGE,
        ACCOUNT_ENABLED,
        ACCOUNT_DISABLED,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        TWO_FACTOR_ENABLED,
        TWO_FACTOR_DISABLED,
        SESSION_TERMINATED,
        ADMIN_ACTION
    }
} 