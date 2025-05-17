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
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
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

/** == 소셜 로그인 흐름 ==
 * role 은 왜 customUserDetails.getAuthorities() 사용하지 않을까 ?
 * > 로그인 인증 처리 시 UserDetailsService에서 CustomUserDetails를 반환.
 * > 스프링 시큐리티는 CustomUserDetails.getAuthorities()를 호출해 권한을 받아서
 * > Authentication 객체에 권한 정보를 저장한다.
 * > 이후에 권한이 필요할 때는 authentication.getAuthorities()로 꺼내 쓰는 게 관례
 *
 *  cookie.setHttpOnly(true);
 *  > 자바스크립트가 탈취하지 못하도록
 *
 *  클라이언트가 소셜 로그인 요청 (예: 카카오 로그인) → OAuth2 인증 서버에서 인증 절차 진행
 * 인증 성공하면 스프링 시큐리티가 CustomOAuth2UserService 같은 서비스에서 사용자 정보 로딩
 * CustomSuccessHandler의 onAuthenticationSuccess가 호출되어 JWT 토큰 생성 → 쿠키에 JWT 담아서 클라이언트에 전달
 * 클라이언트가 쿠키에서 JWT를 읽어 이후 요청에 사용하거나, 쿠키 자동 전송
 * 이후 요청 시 서버가 JwtFilter에서 JWT 검증 → 정상 인증 처리
 */
