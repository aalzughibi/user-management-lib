package com.aiops.usermanagement.service;

import com.aiops.usermanagement.entity.User;

public interface EmailService {
    void sendVerificationEmail(User user, String token);
    
    void sendPasswordResetEmail(User user, String token);
    
    void sendPhoneVerificationEmail(User user, String token);
    
    void sendWelcomeEmail(User user);
    
    void sendAccountLockedEmail(User user);
    
    void sendAccountUnlockedEmail(User user);
    
    void sendRoleChangedEmail(User user, String roleName);
} 