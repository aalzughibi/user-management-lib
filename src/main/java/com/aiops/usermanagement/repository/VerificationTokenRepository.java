package com.aiops.usermanagement.repository;

import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.VerificationToken;
import com.aiops.usermanagement.entity.VerificationToken.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByToken(String token);
    
    Optional<VerificationToken> findByTokenAndTokenType(String token, TokenType tokenType);
    
    List<VerificationToken> findAllByUserAndTokenType(User user, TokenType tokenType);
    
    @Query("SELECT v FROM VerificationToken v WHERE v.user = :user AND v.tokenType = :tokenType AND v.expiryDate > :now AND v.confirmedAt IS NULL")
    Optional<VerificationToken> findValidToken(User user, TokenType tokenType, LocalDateTime now);
    
    @Modifying
    @Query("DELETE FROM VerificationToken v WHERE v.expiryDate < :now")
    void deleteAllExpiredTokens(LocalDateTime now);
    
    @Modifying
    @Query("UPDATE VerificationToken v SET v.confirmedAt = :now WHERE v.token = :token")
    int confirmToken(String token, LocalDateTime now);
} 