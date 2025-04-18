package com.aiops.usermanagement.repository;

import com.aiops.usermanagement.entity.AuditLog;
import com.aiops.usermanagement.entity.AuditLog.ActionType;
import com.aiops.usermanagement.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    Page<AuditLog> findByUser(User user, Pageable pageable);
    
    Page<AuditLog> findByActionType(ActionType actionType, Pageable pageable);
    
    Page<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);
    
    Page<AuditLog> findByUserAndActionTypeAndTimestampBetween(
            User user, 
            ActionType actionType, 
            LocalDateTime start, 
            LocalDateTime end, 
            Pageable pageable);
    
    List<AuditLog> findTop20ByUserOrderByTimestampDesc(User user);
} 