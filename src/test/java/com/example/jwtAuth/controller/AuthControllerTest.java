package com.example.jwtAuth.controller;

import com.example.jwtAuth.dto.AuthRequest;
import com.example.jwtAuth.dto.JwtResponse;
import com.example.jwtAuth.model.Role;
import com.example.jwtAuth.model.User;
import com.example.jwtAuth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    private String accessToken;
    private String refreshToken;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();
        User testUser = new User();
        testUser.setUsername("testUser");
        testUser.setPassword(passwordEncoder.encode("$2a$10$yB/yDpjjxw95ZmNGit7cEO4Z8BTUfzcIj7u8ZxRQ3NISkvA5FnkD6"));
        testUser.setRole(Role.USER);
        testUser.setAccountNonLocked(true);
        testUser.setFailedLoginAttempts(0);
        userRepository.save(testUser);


        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("$2a$10$yB/yDpjjxw95ZmNGit7cEO4Z8BTUfzcIj7u8ZxRQ3NISkvA5FnkD6"));
        admin.setRole(Role.SUPER_ADMIN);
        admin.setAccountNonLocked(true);
        userRepository.save(admin);

        AuthRequest request = new AuthRequest("admin", "$2a$10$yB/yDpjjxw95ZmNGit7cEO4Z8BTUfzcIj7u8ZxRQ3NISkvA5FnkD6");
        ResultActions result = mockMvc.perform(post("/auth/login")
                        .secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        String res = result.andReturn().getResponse().getContentAsString();
        JwtResponse jwtResponse = objectMapper.readValue(res, JwtResponse.class);
        this.accessToken = jwtResponse.getToken();
        this.refreshToken = jwtResponse.getRefreshToken();
    }

    @Test
    void shouldAllowAccessToProtectedEndpoint_whenTokenIsValid() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Some admin things.....here, You get it cause you're admin"));
    }

    @Test
    void shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + "expiredAccessToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));
    }

    @Test
    void shouldRefreshAccessToken_whenValidRefreshTokenIsProvided() throws Exception {
        ResultActions result = mockMvc.perform(get("/auth/refresh-token")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.refreshToken").exists());

        String responseContent = result.andReturn().getResponse().getContentAsString();
        JwtResponse jwtResponse = objectMapper.readValue(responseContent, JwtResponse.class);

        assertThat(jwtResponse.getToken()).isNotNull();
        assertThat(jwtResponse.getRefreshToken()).isNotNull();
    }

    @Test
    void shouldReturnUnauthorized_whenTokenIsInvalid() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + "invalidToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));
    }

    @Test
    @WithMockUser(authorities = {"MODERATOR"})
    void shouldAllowAccessToModeratorEndpoint_whenUserHasModeratorRole() throws Exception {
        mockMvc.perform(get("/moderator")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Some moderator's things.....here, You get it cause you're moderator "));
    }

    @Test
    void shouldReturnForbidden_whenNoTokenIsProvided() throws Exception {
        mockMvc.perform(get("/admin")
                        .secure(true))
                .andExpect(status().isForbidden());
    }
    @Test
    void testAccountLockAfterFiveFailedAttempts() throws Exception {
        AuthRequest invalidAuthRequest = new AuthRequest("testUser", "wrongPassword");

        for (int i = 0; i < 5; i++) {
            // Отправляем 5 неправильных запросов
            mockMvc.perform(post("/auth/login")
                            .secure(true)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidAuthRequest)))
                    .andExpect(status().isUnauthorized()); // Ожидаем статус 401
        }

        // Проверяем, что аккаунт заблокирован после 5 попыток
        User userFromDb = userRepository.findByUsername("testUser").orElseThrow();
        assertThat(userFromDb.isAccountNonLocked()).isFalse(); // Проверка, что аккаунт заблокирован
        assertThat(userFromDb.getFailedLoginAttempts()).isEqualTo(5);
    }

    @Test
    void testLoginAttemptAfterAccountLock() throws Exception {
        // Мокаем неправильные попытки входа
        AuthRequest invalidAuthRequest = new AuthRequest("testUser", "wrongPassword");

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/auth/login")
                            .secure(true)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidAuthRequest)))
                    .andExpect(status().isUnauthorized());
        }

        // После 5 неудачных попыток аккаунт должен быть заблокирован
        mockMvc.perform(post("/auth/login")
                        .secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidAuthRequest)))
                .andExpect(status().isLocked());

        // Проверяем, что аккаунт все еще заблокирован
        User userFromDb = userRepository.findByUsername("testUser").orElseThrow();
        assertThat(userFromDb.isAccountNonLocked()).isFalse();
        assertThat(userFromDb.getFailedLoginAttempts()).isEqualTo(5);
    }


    @Test
    void testAccountUnlockByAdmin() throws Exception {
        User user = new User();
        user.setUsername("lockedUser");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole(Role.USER);
        user.setAccountNonLocked(false); // аккаунт заблокирован
        user.setFailedLoginAttempts(5);
        userRepository.save(user);


        // После этого администратор может разблокировать аккаунт
        mockMvc.perform(get("/admin/unlock/{username}", "lockedUser")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))

                .andExpect(status().isOk()); // Ожидаем статус 200, если администратор разблокировал аккаунт

        // Проверяем, что аккаунт был разблокирован
        User unlockedUser = userRepository.findByUsername("lockedUser").orElseThrow();
        assertThat(unlockedUser.getFailedLoginAttempts()).isEqualTo(0); // к-во неправильных входов сброшенно
        assertThat(unlockedUser.isAccountNonLocked()).isTrue(); // Аккаунт разблокирован
    }

}

