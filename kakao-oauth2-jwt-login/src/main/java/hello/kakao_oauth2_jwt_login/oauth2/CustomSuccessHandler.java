package hello.kakao_oauth2_jwt_login.oauth2;

import hello.kakao_oauth2_jwt_login.dto.PrincipalUser;
import hello.kakao_oauth2_jwt_login.jwt.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        PrincipalUser principalUser = (PrincipalUser) authentication.getPrincipal();
        String nickname = principalUser.getNickname();
        String username = principalUser.getName();
        String provider = principalUser.getProvider();
        String providerId = principalUser.getProviderId();
        String role = getRoleFromAuthentication(authentication);

        String token = jwtUtil.createJwt(nickname, username, role, provider, providerId, 60 * 60 * 10L);
        response.addCookie(createCookie("Authorization", token));

        getRedirectStrategy().sendRedirect(request, response, "/");
    }

    private String getRoleFromAuthentication(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        return auth.getAuthority();
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(216);
        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
