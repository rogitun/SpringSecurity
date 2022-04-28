package com.cos.security1.model;

import lombok.Data;

//Output으로 사용
@Data
public class UserResponse {
    private final String jwt;

    public UserResponse(String jwt) {
        this.jwt = jwt;
    }
}
