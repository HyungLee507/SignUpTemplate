package com.ssafy.template.global.jwt.provider;

import com.ssafy.template.member.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


/**
 * JWT 토큰의 생성 및 검증을 담당하는 클래스.
 * <p>
 * 이 클래스는 JWT 기반의 인증 시스템에서 Access Token과 Refresh Token을 생성하고, 클라이언트가 제공한 JWT의 유효성을 검증하는 역할을 합니다.
 * </p>
 *
 * <h2>주요 기능:</h2>
 * <ul>
 *     <li>Access Token 및 Refresh Token 생성</li>
 *     <li>JWT의 유효성 검증</li>
 *     <li>JWT에서 사용자 정보(이메일, memberId) 추출</li>
 * </ul>
 *
 * <h2>토큰 정보:</h2>
 * <ul>
 *     <li>Access Token: 짧은 유효기간을 가지며, 사용자의 인증 정보 확인에 사용됨</li>
 *     <li>Refresh Token: 더 긴 유효기간을 가지며, Access Token이 만료되었을 때 새로 발급하는 용도로 사용됨</li>
 * </ul>
 *
 * @author Your Name
 * @since 1.0
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final Key accessKey;
    private final Key refreshKey;

    @Value("${jwt.access.expiration-time}")
    private long accessExpiration;

    @Value("${jwt.refresh.expiration-time}")
    private long refreshExpiration;

    private final

    public JwtTokenProvider(@Value("${jwt.access.secret-key}") String accessSecret,
                            @Value("${jwt.refresh.secret-key}") String refreshSecret) {
        this.accessKey = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
        this.refreshKey = Keys.hmacShaKeyFor(refreshSecret.getBytes(StandardCharsets.UTF_8));
    }

    // access Token 생성 메서드
    public String generateAccessToken(Long memberId, String email) {
        return Jwts.builder()
                .setSubject(email)
                .claim("memberId", memberId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessExpiration))
                .signWith(accessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // refresh Token 생성 메서드
    public String generateRefreshToken(Long memberId, String email) {
        return Jwts.builder()
                .setSubject(email)
                .claim("memberId", memberId) // ✅ memberId 포함
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(refreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // jwt 토큰 검증 메서드
    public boolean validateToken(String token, boolean isRefreshToken) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(isRefreshToken ? refreshKey : accessKey)
                    .build()
                    .parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            log.warn("JWT 만료됨: {}", e.getMessage());
            return false; // ✅ 만료된 경우 로그 추가
        } catch (Exception e) {
            log.error("JWT 검증 실패: {}", e.getMessage());
            return false;
        }
    }

    // jwt 토큰에서 이메일(사용자 정보) 추출
    public String getEmailFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(accessKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // jwt 토큰에서 사용자 id 추출
    public Long getMemberIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(accessKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("memberId", Long.class); // ✅ memberId 값 가져오기
    }

    public Authentication getAuthentication(String token) {
        String email = getEmailFromToken(token);
        Long memberId = getMemberIdFromToken(token);

        // ✅ 데이터베이스에서 Member 조회 (이미 존재하는 회원인지 확인)
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다."));

        // ✅ Spring Security의 Authentication 객체 생성
        return new UsernamePasswordAuthenticationToken(member, token,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    }

}
