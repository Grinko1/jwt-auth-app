CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    failed_login_attempts INT DEFAULT 0,
    role VARCHAR(20) NOT NULL,
    is_account_non_locked BOOLEAN DEFAULT TRUE
);