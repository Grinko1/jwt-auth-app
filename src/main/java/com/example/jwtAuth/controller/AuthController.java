package com.example.jwtAuth.controller;

import com.example.jwtAuth.config.jwt.JWTUtils;
import com.example.jwtAuth.dto.JwtResponse;
import com.example.jwtAuth.dto.AuthRequest;
import com.example.jwtAuth.service.AuthenticationService;
import com.example.jwtAuth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final JWTUtils jwtUtils;
    private final UserService userService;

    public AuthController(AuthenticationService authenticationService, JWTUtils jwtService, UserService userService) {
        this.authenticationService = authenticationService;
        this.jwtUtils = jwtService;
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtResponse> signUp(@RequestBody @Valid AuthRequest request) {
        JwtResponse response = authenticationService.signUp(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody @Valid AuthRequest request) {
        JwtResponse response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<JwtResponse> refreshToken(@RequestHeader("Authorization") String refreshTokenHeader) {
        String refreshToken = refreshTokenHeader.substring(7).trim();

        if (jwtUtils.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String username = jwtUtils.extractUserName(refreshToken);
        UserDetails userDetails = userService.getByUsername(username);

        JwtResponse response = new JwtResponse(jwtUtils.generateToken(userDetails), jwtUtils.generateRefreshToken(userDetails));
        return ResponseEntity.ok(response);
    }
}