package com.cos.security1.model;

import lombok.Data;
import lombok.NoArgsConstructor;

// Input으로 사용
@Data
@NoArgsConstructor
public class UserRequest {
    private String username;
    private String password;

    public UserRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
