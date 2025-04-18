package com.aiops.usermanagement.controller;

import com.aiops.usermanagement.dto.request.LoginRequest;
import com.aiops.usermanagement.dto.request.PasswordResetRequest;
import com.aiops.usermanagement.dto.request.RegisterRequest;
import com.aiops.usermanagement.dto.response.ApiResponse;
import com.aiops.usermanagement.dto.response.JwtResponse;
import com.aiops.usermanagement.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        JwtResponse jwtResponse = authService.login(loginRequest, request);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest registerRequest) {
        authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User registered successfully. Please check your email for verification."));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(ApiResponse.success("Email verified successfully."));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestParam String email) {
        authService.requestPasswordReset(email);
        return ResponseEntity.ok(ApiResponse.success("Password reset email sent. Please check your email."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetRequest resetRequest) {
        authService.resetPassword(resetRequest);
        return ResponseEntity.ok(ApiResponse.success("Password reset successfully."));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refreshToken(@RequestParam String refreshToken) {
        JwtResponse jwtResponse = authService.refreshToken(refreshToken);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String token) {
        authService.logout(token);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully."));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Void>> resendVerification(@RequestParam String email) {
        authService.resendVerificationEmail(email);
        return ResponseEntity.ok(ApiResponse.success("Verification email resent. Please check your email."));
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<ApiResponse<Void>> verifyTwoFactorCode(
            @RequestParam String email, 
            @RequestParam String code) {
        authService.verifyTwoFactorCode(email, code);
        return ResponseEntity.ok(ApiResponse.success("Two-factor authentication successful."));
    }

    @PostMapping("/request-phone-verification")
    public ResponseEntity<ApiResponse<Void>> requestPhoneVerification(@RequestParam String phone) {
        authService.requestPhoneVerification(phone);
        return ResponseEntity.ok(ApiResponse.success("Phone verification code sent. Please check your email."));
    }

    @GetMapping("/verify-phone")
    public ResponseEntity<ApiResponse<Void>> verifyPhone(@RequestParam String token) {
        authService.verifyPhone(token);
        return ResponseEntity.ok(ApiResponse.success("Phone number verified successfully."));
    }
} 