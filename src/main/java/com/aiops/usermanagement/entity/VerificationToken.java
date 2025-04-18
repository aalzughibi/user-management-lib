package com.aiops.usermanagement.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "verification_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String token;
    
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType;
    
    @Column(nullable = false)
    private LocalDateTime expiryDate;
    
    private LocalDateTime confirmedAt;
    
    private String additionalInfo;
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }
    
    public boolean isConfirmed() {
        return confirmedAt != null;
    }
    
    public enum TokenType {
        EMAIL_VERIFICATION,
        PASSWORD_RESET,
        PHONE_VERIFICATION,
        TWO_FACTOR_AUTHENTICATION
    }
} 