package com.aiops.usermanagement.service;

import com.aiops.usermanagement.entity.AuditLog;
import com.aiops.usermanagement.entity.AuditLog.ActionType;
import com.aiops.usermanagement.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;

public interface AuditService {
    void logUserAction(User user, ActionType actionType, String description, HttpServletRequest request);
    
    Page<AuditLog> getUserActivityLogs(Long userId, Pageable pageable);
    
    Page<AuditLog> getActivityLogsByType(ActionType actionType, Pageable pageable);
    
    Page<AuditLog> getActivityLogsBetweenDates(LocalDateTime start, LocalDateTime end, Pageable pageable);
    
    Page<AuditLog> getActivityLogs(Long userId, ActionType actionType, LocalDateTime start, LocalDateTime end, Pageable pageable);
    
    List<AuditLog> getRecentUserActivityLogs(Long userId);
} 