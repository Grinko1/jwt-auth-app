package com.example.jwtAuth.exceptions;

public class UserLockedException extends RuntimeException{
    public UserLockedException(String message) {
        super(message);
    }
}