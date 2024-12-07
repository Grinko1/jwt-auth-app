package com.example.jwtAuth.service;

import com.example.jwtAuth.exceptions.UserNotFoundException;
import com.example.jwtAuth.exceptions.UserAlreadyExistsException;
import com.example.jwtAuth.model.User;
import com.example.jwtAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    @Autowired
    private UserRepository userRepository;

    private User persistUser(User user) {
        return userRepository.save(user);
    }

    // Создание нового пользователя
    public User createUser(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new UserAlreadyExistsException("User with username '%s' already exists".formatted(user.getUsername()));
        }
        return persistUser(user);
    }

    // Получение пользователя по имени
    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User with username '%s' not found".formatted(username)));
    }

    // Получение текущего аутентифицированного пользователя
    public User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }

    // Увеличение количества неудачных попыток входа
    public void incrementFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= 5) {
            user.setAccountNonLocked(false);  // Блокируем аккаунт после 5 неудачных попыток
        }
        persistUser(user);
    }
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    // Разблокировка пользователя
    public void unlockUser(String username) {
        User user = getByUsername(username);
        if (!user.isAccountNonLocked()) {
            user.setFailedLoginAttempts(0);
            user.setAccountNonLocked(true);
            persistUser(user);
        }
    }
}
