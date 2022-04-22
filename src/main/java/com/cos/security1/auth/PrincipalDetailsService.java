package com.cos.security1.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessUrl 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는  loadUserByUsername 함수가 실행
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    //시큐리티 세션 = Authentication = UserDetails(현재 principal)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //파라미터의 username은 유저가 로그인할때 사용하는 로그인 아이디이다.
        User user = userRepository.findByUsername(username);
        if(user != null){
            //유저가 존재함
            return new PrincipalDetails(user);
        }
        return null;
    }
}
