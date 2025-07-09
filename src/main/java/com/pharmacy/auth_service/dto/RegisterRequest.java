package com.pharmacy.auth_service.dto;

import com.pharmacy.auth_service.entity.Role;
import lombok.Data;

@Data
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
    private Role role; // ADMIN or PHARMACIST
}
