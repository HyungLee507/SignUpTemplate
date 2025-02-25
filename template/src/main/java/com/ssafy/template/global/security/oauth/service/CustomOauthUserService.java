package com.ssafy.template.global.security.oauth.service;

import com.ssafy.template.global.security.util.CustomUserDetail;
import com.ssafy.template.member.entity.AuthProvider;
import com.ssafy.template.member.entity.Member;
import com.ssafy.template.member.repository.MemberRepository;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class CustomOauthUserService {

    private final MemberRepository memberRepository;

    public CustomUserDetail loadUser(OAuth2AuthenticationToken token) {
        OAuth2User oAuth2User = token.getPrincipal();
        String registrationId = token.getAuthorizedClientRegistrationId(); // google, kakao, naver
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String email = extractEmail(registrationId, attributes);

        // 사용자 정보가 DB에 없으면 회원가입 진행
        Optional<Member> existingMember = memberRepository.findByEmail(email);
        Member member = existingMember.orElseGet(() -> memberRepository.save(
                Member.builder()
                        .email(email)
                        .authProvider(AuthProvider.valueOf(registrationId.toUpperCase()))
                        .build()
        ));

        return new CustomUserDetail(member);
    }

    private String extractEmail(String provider, Map<String, Object> attributes) {
        switch (provider) {
            case "google":
                return (String) attributes.get("email");
            case "kakao":
                return (String) ((Map<String, Object>) attributes.get("kakao_account")).get("email");
            case "naver":
                return (String) ((Map<String, Object>) attributes.get("response")).get("email");
            default:
                throw new IllegalArgumentException("지원되지 않는 OAuth Provider: " + provider);
        }
    }
}
