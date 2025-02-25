package com.ssafy.template.global.jwt.repository;

import com.ssafy.template.global.jwt.entity.RefreshToken;
import com.ssafy.template.member.entity.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByMember(Member member);

    void deleteByMember(Member member);
}
