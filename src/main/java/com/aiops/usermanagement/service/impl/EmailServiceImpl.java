package com.aiops.usermanagement.service.impl;

import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    @Value("${server.servlet.context-path}")
    private String contextPath;
    
    @Value("${server.port}")
    private String serverPort;

    @Override
    @Async
    public void sendVerificationEmail(User user, String token) {
        try {
            String verificationUrl = "http://localhost:" + serverPort + contextPath + "/auth/verify-email?token=" + token;
            
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            context.setVariable("verificationUrl", verificationUrl);
            
            String content = templateEngine.process("email/email-verification", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Please verify your email address");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Verification email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendPasswordResetEmail(User user, String token) {
        try {
            String resetUrl = "http://localhost:" + serverPort + contextPath + "/auth/reset-password?token=" + token;
            
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            context.setVariable("resetUrl", resetUrl);
            
            String content = templateEngine.process("email/password-reset", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Password Reset Request");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Password reset email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendPhoneVerificationEmail(User user, String token) {
        try {
            String verificationUrl = "http://localhost:" + serverPort + contextPath + "/auth/verify-phone?token=" + token;
            
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("phone", user.getPhone());
            
            String content = templateEngine.process("email/phone-verification", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Verify your phone number");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Phone verification email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send phone verification email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendWelcomeEmail(User user) {
        try {
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            
            String content = templateEngine.process("email/welcome", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Welcome to our platform!");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Welcome email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send welcome email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendAccountLockedEmail(User user) {
        try {
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            
            String content = templateEngine.process("email/account-locked", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Your account has been locked");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Account locked email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send account locked email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendAccountUnlockedEmail(User user) {
        try {
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            
            String content = templateEngine.process("email/account-unlocked", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Your account has been unlocked");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Account unlocked email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send account unlocked email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    @Async
    public void sendRoleChangedEmail(User user, String roleName) {
        try {
            Context context = new Context();
            context.setVariable("name", user.getFullName());
            context.setVariable("role", roleName);
            
            String content = templateEngine.process("email/role-changed", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject("Your account role has been updated");
            helper.setText(content, true);
            
            mailSender.send(message);
            
            log.info("Role changed email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send role changed email to {}: {}", user.getEmail(), e.getMessage());
        }
    }
} 