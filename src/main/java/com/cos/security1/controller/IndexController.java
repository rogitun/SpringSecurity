//package com.cos.security1.controller;
//
//import com.cos.security1.model.User;
//import com.cos.security1.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.access.annotation.Secured;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.ResponseBody;
//
//@Controller
//@RequiredArgsConstructor
//public class IndexController {
//
//    private final UserRepository userRepository;
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//
//
//    @GetMapping("/")
//    public String index(){
//        return "index";
//    }
//
//    @ResponseBody
//    @GetMapping("/user")
//    public String user(){
//        return "user";
//    }
//
//    @ResponseBody
//    @GetMapping("/admin")
//    public String admin(){
//        return "admin";
//    }
//
//    @ResponseBody
//    @GetMapping("/manager")
//    public String manager(){
//        return "manager";
//    }
//
//    @GetMapping("/loginForm")
//    public String loginForm(){
//        return "loginForm";
//    }
//
//    @PostMapping("/join")
//    public String join(User user){
//        user.setRole("USER");
//        String rawPassword = user.getPassword();
//        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
//        user.setPassword(encPassword);
//        userRepository.save(user);
//        return "redirect:/loginForm";
//    }
//
//    @GetMapping("/joinForm")
//    public String joinForm (){
//        return "joinForm";
//    }
//
//    @ResponseBody
//    @Secured("ROLE_ADMIN") //권한으로 제한 가능
//    @GetMapping("/info")
//    public String info(){
//        return "개인정보 : ";
//    }
//
//    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //메서드 실행 전에 제한 가능
//    @GetMapping("/data")
//    public String data(){
//        return "개인정보 : ";
//    }
//
//}
