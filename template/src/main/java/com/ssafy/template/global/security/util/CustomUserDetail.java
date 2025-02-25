package com.ssafy.template.global.security.util;

import com.ssafy.template.member.entity.Member;
import java.util.Collection;
import java.util.Collections;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Spring Security Context에 사용자 정보를 저장
 */
@Getter
public class CustomUserDetail implements UserDetails {

    private final Member member;

    public CustomUserDetail(Member member) {
        this.member = member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList(); // 권한 관리 필요하면 수정
    }


    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getEmail();
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
