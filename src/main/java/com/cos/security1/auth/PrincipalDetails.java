package com.cos.security1.auth;

//시큐리티가 로그인 url을 낚아채서 로그인을 진행시킨다.
// 로그인이 진행 완료되면 시큐리티 session을 만들어준다.(Security ContextHolder)
// 세션에 저장되는 오브젝트 => Authentication 타입의 객체
// Authentication 안에 User 정보가 있어야함.
// User Object 타입 => UserDetails 타입의 객체

//시큐리티 세션에 저장되는 객체는 Authentication, Authentication에 저장되는 유저 객체는 UserDetails

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {


    private User user; //콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    //해당 유저의 권한을 리턴한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        //사이트에서 특정 기간동안 접근이 없어 휴먼 계정으로 전환


        return true;
    }
}
