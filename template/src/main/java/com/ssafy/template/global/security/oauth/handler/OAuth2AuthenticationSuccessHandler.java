package com.ssafy.template.global.security.oauth.handler;

import com.ssafy.template.global.jwt.provider.JwtTokenProvider;
import com.ssafy.template.global.security.oauth.service.CustomOauthUserService;
import com.ssafy.template.global.security.util.CustomUserDetail;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;


@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomOauthUserService oauthUserService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        CustomUserDetail userDetails = oauthUserService.loadUser(oauthToken);

        // JWT 발급
        String accessToken = jwtTokenProvider.generateAccessToken(userDetails.getMemberId(), userDetails.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails.getMemberId(), userDetails.getEmail());

        response.getWriter().write("AccessToken: " + accessToken + ", RefreshToken: " + refreshToken);
    }
}
