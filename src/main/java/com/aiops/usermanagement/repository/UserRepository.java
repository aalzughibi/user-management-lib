package com.aiops.usermanagement.repository;

import com.aiops.usermanagement.entity.User;
import com.aiops.usermanagement.entity.User.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    
    Optional<User> findByPhone(String phone);
    
    Boolean existsByEmail(String email);
    
    Boolean existsByPhone(String phone);
    
    @Query("SELECT u FROM User u WHERE " +
           "(LOWER(u.fullName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "u.phone LIKE CONCAT('%', :searchTerm, '%')) " +
           "AND (:status IS NULL OR u.status = :status)")
    Page<User> searchUsers(@Param("searchTerm") String searchTerm, 
                           @Param("status") UserStatus status, 
                           Pageable pageable);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :startDate AND u.createdAt <= :endDate")
    Long countUsersRegisteredBetween(@Param("startDate") LocalDateTime startDate, 
                                    @Param("endDate") LocalDateTime endDate);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.lastLoginAt >= :since")
    Long countActiveUsersSince(@Param("since") LocalDateTime since);
    
    Page<User> findAllByStatus(UserStatus status, Pageable pageable);
} 