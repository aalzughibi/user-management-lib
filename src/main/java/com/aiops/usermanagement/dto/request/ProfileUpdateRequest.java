package com.aiops.usermanagement.dto.request;

import com.aiops.usermanagement.entity.User.Gender;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProfileUpdateRequest {
    
    @Size(min = 2, max = 100, message = "Full name must be between 2 and 100 characters")
    private String fullName;
    
    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "Phone number must be valid")
    private String phone;
    
    private Gender gender;
    
    @Past(message = "Birthdate must be in the past")
    private LocalDate birthdate;
    
    @Size(max = 255, message = "Address cannot exceed 255 characters")
    private String address;
} 