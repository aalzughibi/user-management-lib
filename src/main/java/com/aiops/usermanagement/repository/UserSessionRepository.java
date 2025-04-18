package com.aiops.usermanagement.repository;

import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.UserSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByToken(String token);
    
    Optional<UserSession> findByRefreshToken(String refreshToken);
    
    List<UserSession> findByUserAndActiveTrue(User user);
    
    Page<UserSession> findByUser(User user, Pageable pageable);
    
    @Modifying
    @Query("UPDATE UserSession s SET s.active = false, s.terminatedAt = :now, s.terminationReason = :reason WHERE s.user = :user AND s.active = true")
    int deactivateAllUserSessions(User user, LocalDateTime now, UserSession.TerminationReason reason);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false, s.terminatedAt = :now, s.terminationReason = :reason WHERE s.token = :token")
    int deactivateSession(String token, LocalDateTime now, UserSession.TerminationReason reason);
    
    @Modifying
    @Query("UPDATE UserSession s SET s.lastAccessedAt = :now WHERE s.token = :token")
    int updateLastAccessed(String token, LocalDateTime now);
    
    @Modifying
    @Query("UPDATE UserSession s SET s.active = false, s.terminatedAt = :now, s.terminationReason = 'SESSION_EXPIRED' WHERE s.expiresAt < :now AND s.active = true")
    int deactivateExpiredSessions(LocalDateTime now);
    
    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user = :user AND s.active = true")
    long countActiveSessions(User user);
} 