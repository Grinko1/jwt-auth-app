package com.example.jwtAuth.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Entity
@Builder
@Getter
@Setter
//@NoArgsConstructor
//@AllArgsConstructor
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private int failedLoginAttempts = 0;
    @Enumerated(EnumType.STRING)
    private Role role;
    private boolean isAccountNonLocked;


    public User(Long id, String username, String password, int failedLoginAttempts, Role role, boolean isAccountNonLocked) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.failedLoginAttempts = failedLoginAttempts;
        this.role = role;
        this.isAccountNonLocked = isAccountNonLocked;
    }

    public User(String username, String password, int failedLoginAttempts, Role role, boolean isAccountNonLocked) {
        this.username = username;
        this.password = password;
        this.failedLoginAttempts = failedLoginAttempts;
        this.role = role;
        this.isAccountNonLocked = isAccountNonLocked;
    }

    public User() {
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        isAccountNonLocked = accountNonLocked;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(role);
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
