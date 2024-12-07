package com.example.jwtAuth.service;

import com.example.jwtAuth.config.jwt.JWTUtils;
import com.example.jwtAuth.dto.AuthRequest;
import com.example.jwtAuth.dto.JwtResponse;
import com.example.jwtAuth.exceptions.InvalidTokenException;
import com.example.jwtAuth.exceptions.UserLockedException;
import com.example.jwtAuth.exceptions.UserNotFoundException;
import com.example.jwtAuth.model.Role;
import com.example.jwtAuth.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
//@RequiredArgsConstructor
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private final UserService userService;
    private final JWTUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserService userService, JWTUtils jwtU, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtUtils = jwtU;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public JwtResponse signUp(AuthRequest request) {

        User user = new User(request.getUsername(),
                passwordEncoder.encode(request.getPassword()),
                0,
                Role.USER,
                true);
        userService.createUser(user);

        logger.info("User '{}' signed up", request.getUsername());

        String jwt = jwtUtils.generateToken(user);
        String refreshJwt = jwtUtils.generateRefreshToken(user);
        logger.info("Generated JWT for user {}", request.getUsername());

        return new JwtResponse(jwt, refreshJwt);
    }

    public JwtResponse login(AuthRequest request) {
        User user = userService.getByUsername(request.getUsername());
        if (!user.isAccountNonLocked()) {
            logger.warn("User '{}' account is locked, too many failed login attempts.", request.getUsername());
            throw new UserLockedException("Your account is locked, too many failed login attempts");
        }

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            ));
            logger.info("User '{}' login", request.getUsername());

            String jwt = jwtUtils.generateToken(user);
            String refreshJwt = jwtUtils.generateRefreshToken(user);
            logger.info("Generated JWT for user {}", request.getUsername());

            return new JwtResponse(jwt, refreshJwt);

        } catch (BadCredentialsException e) {
            logger.warn("User '{}' failed to login: {}", request.getUsername(), e.getMessage());
            userService.incrementFailedLoginAttempts(user);
            throw new BadCredentialsException("Wrong username or password");

        }catch (UsernameNotFoundException e){
            logger.warn("User '{}' not found: {}", request.getUsername(), e.getMessage());
            throw new UserNotFoundException("User with username '%s' not found".formatted(request.getUsername()));
        }
    }

    public JwtResponse refreshJwtToken(String refreshToken) {
        UserDetails userDetails = userService.getCurrentUser();

        if (jwtUtils.isRefreshTokenValid(refreshToken, userDetails)) {
            String newAccessToken = jwtUtils.generateToken(userDetails);
            return new JwtResponse(newAccessToken, refreshToken);
        } else {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }
    }
}