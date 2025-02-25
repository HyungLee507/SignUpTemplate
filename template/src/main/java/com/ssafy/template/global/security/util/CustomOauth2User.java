package com.ssafy.template.global.security.util;

import com.ssafy.template.member.entity.Member;
import java.util.Collection;
import java.util.Collections;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Getter
public class CustomOauth2User implements UserDetails {

    private final Long memberId;
    private final String email;

    public CustomOauth2User(Member member) {
        this.memberId = member.getId();
        this.email = member.getEmail();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList(); // 필요하면 ROLE 추가 가능
    }

    @Override
    public String getPassword() {
        return null; // 소셜 로그인에서는 비밀번호 없음
    }

    @Override
    public String getUsername() {
        return email;
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
        return true;
    }
}
