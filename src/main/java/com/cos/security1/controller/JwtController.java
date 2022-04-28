package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.auth.PrincipalDetailsService;
import com.cos.security1.config.JwtUtil;
import com.cos.security1.model.User;
import com.cos.security1.model.UserRequest;
import com.cos.security1.model.UserResponse;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwtController {

    private final AuthenticationManager authenticationManager;
    private final PrincipalDetailsService principalDetailsService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @PostMapping("/authenticate/save")
    public String join(@RequestBody UserRequest request){
        User user = new User();
        user.setUsername(request.getUsername());
        String pwd = request.getPassword();
        user.setPassword(passwordEncoder.encode(pwd));
        userRepository.save(user);
        return "good";
    }


    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserRequest userRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userRequest.getUsername(),userRequest.getPassword())
            );
            //인증이 실패하면
        }catch(BadCredentialsException e){
            throw new Exception("부정확한 정보입니다.",e);
        }
        final PrincipalDetails userDetails = (PrincipalDetails) principalDetailsService.loadUserByUsername(userRequest.getUsername());

        final String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new UserResponse(jwt));
    }
}
