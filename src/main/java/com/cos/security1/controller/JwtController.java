package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.auth.PrincipalDetailsService;
import com.cos.security1.config.JwtUtil;
import com.cos.security1.model.User;
import com.cos.security1.model.UserRequest;
import com.cos.security1.model.UserResponse;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.function.Function;


@RestController
@RequiredArgsConstructor
@Slf4j
public class JwtController {

    private final AuthenticationManager authenticationManager;
    private final PrincipalDetailsService principalDetailsService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/hello")
    public String hello(){
        //String authorization = request.getHeader("Authorization");
        //권한이 되는지 체크 필요함
        //Boolean aBoolean = jwtUtil.validateToken(authorization.substring(7), temp);//bearer 제외하고
        //System.out.println(aBoolean);
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
            log.info("Authentication Manager call");
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userRequest.getUsername(),userRequest.getPassword())
            );
            //인증이 실패하면
        }catch(BadCredentialsException e){
            throw new Exception("BadCredential.",e);
        }
        System.out.println("############ Authentication Pass ##############");
        final PrincipalDetails userDetails = (PrincipalDetails) principalDetailsService.loadUserByUsername(userRequest.getUsername());

        final String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new UserResponse(jwt));
    }
}
