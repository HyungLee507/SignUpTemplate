package com.ssafy.template.global.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // 🚀 운영 환경 (로컬 개발 허용, 배포 시 localhost 제거 가능)
        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://localhost:8080",
                "https://togethrebuy.com",
                "https://www.togethrebuy.com"
        ));

        // HTTP 메서드 허용
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        // 모든 요청 헤더 허용
        config.setAllowedHeaders(List.of("*"));

        // 클라이언트가 접근할 수 있는 응답 헤더
        config.setExposedHeaders(List.of("Authorization", "Set-Cookie"));

        // 자격 증명 허용 (쿠키, Authorization 토큰 등)
        config.setAllowCredentials(true);

        // 모든 API 경로에 대해 CORS 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
