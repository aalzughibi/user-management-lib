package com.aiops.usermanagement.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    
    @NotBlank(message = "Username/Email/Phone is required")
    private String usernameOrEmailOrPhone;
    
    @NotBlank(message = "Password is required")
    private String password;
    
    private boolean rememberMe = false;
    
    private String otpCode;
} 