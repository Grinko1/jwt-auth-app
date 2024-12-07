package com.example.jwtAuth.controller;

import com.example.jwtAuth.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasAuthority('SUPER_ADMIN')")
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<String> adminPage() {
        return ResponseEntity.ok("Some admin things.....here, You get it cause you're admin");
    }

    @GetMapping("/unlock/{username}")
    public ResponseEntity<String> unlockUser(@PathVariable String username) {
        userService.unlockUser(username);
        return ResponseEntity.ok("User '%s' was unlocked ".formatted(username));

    }
}