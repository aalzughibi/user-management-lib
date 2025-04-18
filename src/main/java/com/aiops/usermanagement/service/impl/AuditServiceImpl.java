package com.aiops.usermanagement.service.impl;

import com.aiops.usermanagement.entity.AuditLog;
import com.aiops.usermanagement.entity.AuditLog.ActionType;
import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.repository.AuditLogRepository;
import com.aiops.usermanagement.repository.UserRepository;
import com.aiops.usermanagement.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {

    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    @Override
    public void logUserAction(User user, ActionType actionType, String description, HttpServletRequest request) {
        AuditLog log = AuditLog.builder()
                .user(user)
                .actionType(actionType)
                .description(description)
                .timestamp(LocalDateTime.now())
                .build();
        
        if (request != null) {
            log.setIpAddress(getClientIp(request));
            log.setUserAgent(request.getHeader("User-Agent"));
        }
        
        auditLogRepository.save(log);
    }

    @Override
    public Page<AuditLog> getUserActivityLogs(Long userId, Pageable pageable) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return auditLogRepository.findByUser(user, pageable);
    }

    @Override
    public Page<AuditLog> getActivityLogsByType(ActionType actionType, Pageable pageable) {
        return auditLogRepository.findByActionType(actionType, pageable);
    }

    @Override
    public Page<AuditLog> getActivityLogsBetweenDates(LocalDateTime start, LocalDateTime end, Pageable pageable) {
        return auditLogRepository.findByTimestampBetween(start, end, pageable);
    }

    @Override
    public Page<AuditLog> getActivityLogs(Long userId, ActionType actionType, LocalDateTime start, LocalDateTime end, Pageable pageable) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return auditLogRepository.findByUserAndActionTypeAndTimestampBetween(user, actionType, start, end, pageable);
    }

    @Override
    public List<AuditLog> getRecentUserActivityLogs(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return auditLogRepository.findTop20ByUserOrderByTimestampDesc(user);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
} 