package com.ssafy.template.global.security.util;

import java.security.AuthProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtil {

    public static AuthProvider getCurrentAuthProvider() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getPrincipal() == "anonymousUser") {
            throw new RuntimeException("No authentication found");
        }

        return ((CustomUserDetail) authentication.getPrincipal()).getAuthProvider();
    }
}
