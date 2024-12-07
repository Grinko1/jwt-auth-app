package com.example.jwtAuth.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ErrorResponse {
    private String error;
    private Object message;

    public ErrorResponse(String error, Object message) {
        this.error = error;
        this.message = message;
    }
}