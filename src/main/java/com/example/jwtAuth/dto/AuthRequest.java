package com.example.jwtAuth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

//@Data
//@AllArgsConstructor
public class AuthRequest {

    @NotBlank(message = "Username must be field")
    private String username;

    @NotBlank(message = "Password must be field")
    private String password;

    public AuthRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
