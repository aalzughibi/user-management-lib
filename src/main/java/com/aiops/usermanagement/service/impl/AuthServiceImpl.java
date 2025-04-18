package com.aiops.usermanagement.service.impl;

import com.aiops.usermanagement.dto.request.LoginRequest;
import com.aiops.usermanagement.dto.request.PasswordResetRequest;
import com.aiops.usermanagement.dto.request.RegisterRequest;
import com.aiops.usermanagement.dto.response.JwtResponse;
import com.aiops.usermanagement.entity.Role;
import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.UserSession;
import com.aiops.usermanagement.entity.VerificationToken;
import com.aiops.usermanagement.exception.BadRequestException;
import com.aiops.usermanagement.exception.ResourceNotFoundException;
import com.aiops.usermanagement.repository.RoleRepository;
import com.aiops.usermanagement.repository.UserRepository;
import com.aiops.usermanagement.repository.UserSessionRepository;
import com.aiops.usermanagement.repository.VerificationTokenRepository;
import com.aiops.usermanagement.security.JwtTokenProvider;
import com.aiops.usermanagement.security.UserPrincipal;
import com.aiops.usermanagement.service.AuditService;
import com.aiops.usermanagement.service.AuthService;
import com.aiops.usermanagement.service.EmailService;
import com.aiops.usermanagement.entity.AuditLog.ActionType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final UserSessionRepository sessionRepository;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;
    private final AuditService auditService;
    
    @Value("${app.email.verification-expiration-minutes}")
    private int verificationExpirationMinutes;
    
    @Value("${app.email.password-reset-expiration-minutes}")
    private int passwordResetExpirationMinutes;

    @Override
    public JwtResponse login(LoginRequest loginRequest, HttpServletRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsernameOrEmailOrPhone(),
                loginRequest.getPassword()
            )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        // Check if two-factor auth is required
        User user = userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
        
        // If 2FA is enabled and we don't have an OTP code, return a partial JWT response
        if (user.isTwoFactorEnabled() && (loginRequest.getOtpCode() == null || loginRequest.getOtpCode().isEmpty())) {
            return JwtResponse.builder()
                    .requiresTwoFactor(true)
                    .twoFactorEnabled(true)
                    .email(user.getEmail())
                    .build();
        }
        
        // If 2FA is enabled, verify the OTP code
        if (user.isTwoFactorEnabled()) {
            boolean otpValid = validateOtpCode(user, loginRequest.getOtpCode());
            if (!otpValid) {
                throw new BadRequestException("Invalid OTP code");
            }
        }
        
        // Generate JWT token
        String jwt = tokenProvider.generateToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken();
        
        // Create a new session
        UserSession session = UserSession.builder()
                .user(user)
                .token(jwt)
                .refreshToken(refreshToken)
                .createdAt(LocalDateTime.now())
                .lastAccessedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMillis(tokenProvider.getJwtExpirationMs()))
                .ipAddress(getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .deviceInfo(getDeviceInfo(request))
                .active(true)
                .build();
        
        sessionRepository.save(session);
        
        // Update last login time
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);
        
        // Log the successful login
        auditService.logUserAction(user, ActionType.LOGIN_SUCCESS, 
                "User logged in", request);
        
        // Get user roles
        List<String> roles = userPrincipal.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        
        return JwtResponse.builder()
                .token(jwt)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .id(userPrincipal.getId())
                .fullName(userPrincipal.getFullName())
                .email(userPrincipal.getEmail())
                .roles(roles)
                .emailVerified(userPrincipal.isEmailVerified())
                .twoFactorEnabled(userPrincipal.isTwoFactorEnabled())
                .requiresTwoFactor(false)
                .build();
    }

    @Override
    @Transactional
    public void register(RegisterRequest registerRequest) {
        // Check if email exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new BadRequestException("Email is already taken");
        }

        // Check if phone exists if provided
        if (registerRequest.getPhone() != null && !registerRequest.getPhone().isEmpty() 
                && userRepository.existsByPhone(registerRequest.getPhone())) {
            throw new BadRequestException("Phone number is already taken");
        }

        // Create new user
        User user = User.builder()
                .fullName(registerRequest.getFullName())
                .email(registerRequest.getEmail())
                .phone(registerRequest.getPhone())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .gender(registerRequest.getGender())
                .birthdate(registerRequest.getBirthdate())
                .address(registerRequest.getAddress())
                .emailVerified(false)
                .phoneVerified(false)
                .enabled(true)
                .status(User.UserStatus.ACTIVE)
                .build();

        // Assign user role
        Role userRole = roleRepository.findByName(Role.ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);
        
        // Create and send verification token
        sendVerificationToken(user, VerificationToken.TokenType.EMAIL_VERIFICATION);
        
        // Log the registration
        auditService.logUserAction(user, ActionType.REGISTRATION, 
                "User registered", null);
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        VerificationToken verificationToken = tokenRepository.findByTokenAndTokenType(
                token, VerificationToken.TokenType.EMAIL_VERIFICATION)
                .orElseThrow(() -> new BadRequestException("Invalid verification token"));
        
        if (verificationToken.isExpired()) {
            throw new BadRequestException("Verification token has expired");
        }
        
        if (verificationToken.isConfirmed()) {
            throw new BadRequestException("Email already verified");
        }
        
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        
        verificationToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(verificationToken);
        
        auditService.logUserAction(user, ActionType.EMAIL_VERIFICATION, 
                "Email verified", null);
    }

    @Override
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        sendVerificationToken(user, VerificationToken.TokenType.PASSWORD_RESET);
        
        auditService.logUserAction(user, ActionType.PASSWORD_RESET, 
                "Password reset requested", null);
    }

    @Override
    @Transactional
    public void resetPassword(PasswordResetRequest resetRequest) {
        VerificationToken token = tokenRepository.findByTokenAndTokenType(
                resetRequest.getToken(), VerificationToken.TokenType.PASSWORD_RESET)
                .orElseThrow(() -> new BadRequestException("Invalid reset token"));
        
        if (token.isExpired()) {
            throw new BadRequestException("Reset token has expired");
        }
        
        if (token.isConfirmed()) {
            throw new BadRequestException("Token already used");
        }
        
        if (!resetRequest.getNewPassword().equals(resetRequest.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }
        
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(resetRequest.getNewPassword()));
        userRepository.save(user);
        
        token.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(token);
        
        // Invalidate all active sessions for security
        sessionRepository.deactivateAllUserSessions(
                user, 
                LocalDateTime.now(), 
                UserSession.TerminationReason.SECURITY_VIOLATION);
        
        auditService.logUserAction(user, ActionType.PASSWORD_RESET, 
                "Password reset completed", null);
    }

    @Override
    public JwtResponse refreshToken(String refreshToken) {
        UserSession session = sessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new BadRequestException("Invalid refresh token"));
        
        if (!session.isActive() || session.isExpired()) {
            throw new BadRequestException("Refresh token expired or invalidated");
        }
        
        User user = session.getUser();
        
        // Generate new JWT token
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userPrincipal, null, userPrincipal.getAuthorities());
        
        String newToken = tokenProvider.generateToken(authentication);
        String newRefreshToken = tokenProvider.generateRefreshToken();
        
        // Update session
        session.setToken(newToken);
        session.setRefreshToken(newRefreshToken);
        session.setLastAccessedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusMillis(tokenProvider.getJwtExpirationMs()));
        sessionRepository.save(session);
        
        // Get user roles
        List<String> roles = userPrincipal.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        
        return JwtResponse.builder()
                .token(newToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .roles(roles)
                .emailVerified(user.isEmailVerified())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .requiresTwoFactor(false)
                .build();
    }

    @Override
    @Transactional
    public void logout(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        
        UserSession session = sessionRepository.findByToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid token"));
        
        if (session.isActive()) {
            session.setActive(false);
            session.setTerminatedAt(LocalDateTime.now());
            session.setTerminationReason(UserSession.TerminationReason.USER_LOGOUT);
            sessionRepository.save(session);
            
            auditService.logUserAction(session.getUser(), ActionType.LOGOUT, 
                    "User logged out", null);
        }
    }

    @Override
    public void resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        if (user.isEmailVerified()) {
            throw new BadRequestException("Email already verified");
        }
        
        sendVerificationToken(user, VerificationToken.TokenType.EMAIL_VERIFICATION);
    }

    @Override
    public void verifyTwoFactorCode(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        if (!validateOtpCode(user, code)) {
            throw new BadRequestException("Invalid OTP code");
        }
    }

    @Override
    public void requestPhoneVerification(String phone) {
        User user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new ResourceNotFoundException("User", "phone", phone));
        
        sendVerificationToken(user, VerificationToken.TokenType.PHONE_VERIFICATION);
    }

    @Override
    @Transactional
    public void verifyPhone(String token) {
        VerificationToken verificationToken = tokenRepository.findByTokenAndTokenType(
                token, VerificationToken.TokenType.PHONE_VERIFICATION)
                .orElseThrow(() -> new BadRequestException("Invalid verification token"));
        
        if (verificationToken.isExpired()) {
            throw new BadRequestException("Verification token has expired");
        }
        
        if (verificationToken.isConfirmed()) {
            throw new BadRequestException("Phone already verified");
        }
        
        User user = verificationToken.getUser();
        user.setPhoneVerified(true);
        userRepository.save(user);
        
        verificationToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(verificationToken);
        
        auditService.logUserAction(user, ActionType.PHONE_VERIFICATION, 
                "Phone verified", null);
    }
    
    // Helper methods
    
    private void sendVerificationToken(User user, VerificationToken.TokenType tokenType) {
        // Generate token
        String token = UUID.randomUUID().toString();
        
        // Set expiry date based on token type
        LocalDateTime expiryDate;
        if (tokenType == VerificationToken.TokenType.PASSWORD_RESET) {
            expiryDate = LocalDateTime.now().plusMinutes(passwordResetExpirationMinutes);
        } else {
            expiryDate = LocalDateTime.now().plusMinutes(verificationExpirationMinutes);
        }
        
        // Create verification token
        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(tokenType)
                .expiryDate(expiryDate)
                .build();
        
        tokenRepository.save(verificationToken);
        
        // Send email based on token type
        switch (tokenType) {
            case EMAIL_VERIFICATION:
                emailService.sendVerificationEmail(user, token);
                break;
            case PASSWORD_RESET:
                emailService.sendPasswordResetEmail(user, token);
                break;
            case PHONE_VERIFICATION:
                // This would typically send an SMS, but we'll use email for this example
                emailService.sendPhoneVerificationEmail(user, token);
                break;
            default:
                break;
        }
    }
    
    private boolean validateOtpCode(User user, String otpCode) {
        // This is a simplified implementation
        // In a real app, you would use a library like Google Authenticator TOTP
        // or verify against a stored OTP code
        
        // For demo purposes, just check if the code is "123456"
        return "123456".equals(otpCode);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
    
    private String getDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        // You could use a library to parse the user agent for more detailed info
        return userAgent != null ? userAgent : "Unknown device";
    }
} 