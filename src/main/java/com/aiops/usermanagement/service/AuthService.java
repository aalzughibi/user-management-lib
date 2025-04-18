package com.aiops.usermanagement.service;

import com.aiops.usermanagement.dto.request.LoginRequest;
import com.aiops.usermanagement.dto.request.PasswordResetRequest;
import com.aiops.usermanagement.dto.request.RegisterRequest;
import com.aiops.usermanagement.dto.response.JwtResponse;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    JwtResponse login(LoginRequest loginRequest, HttpServletRequest request);
    
    void register(RegisterRequest registerRequest);
    
    void verifyEmail(String token);
    
    void requestPasswordReset(String email);
    
    void resetPassword(PasswordResetRequest resetRequest);
    
    JwtResponse refreshToken(String refreshToken);
    
    void logout(String token);
    
    void resendVerificationEmail(String email);
    
    void verifyTwoFactorCode(String email, String code);
    
    void requestPhoneVerification(String phone);
    
    void verifyPhone(String token);
} 