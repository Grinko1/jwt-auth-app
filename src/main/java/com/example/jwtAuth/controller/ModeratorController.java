package com.example.jwtAuth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasAuthority('MODERATOR')")
@RequestMapping("/moderator")
public class ModeratorController {

    @GetMapping
    public ResponseEntity<String> moderatorPage() {
        return ResponseEntity.ok("Some moderator's things.....here, You get it cause you're moderator ");
    }
}
