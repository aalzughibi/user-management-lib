package com.aiops.usermanagement.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long id;
    private String fullName;
    private String email;
    private List<String> roles;
    private boolean emailVerified;
    private boolean twoFactorEnabled;
    private boolean requiresTwoFactor;
} 