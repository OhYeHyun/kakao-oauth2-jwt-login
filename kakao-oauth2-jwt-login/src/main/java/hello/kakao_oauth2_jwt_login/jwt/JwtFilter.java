package hello.kakao_oauth2_jwt_login.jwt;

import hello.kakao_oauth2_jwt_login.dto.PrincipalUser;
import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if (path.startsWith("/login") || path.startsWith("/oauth2") || path.startsWith("/join") || path.startsWith("/image")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractTokenFromCookies(request.getCookies());
        if (token == null) {
            log.info("token null");
            filterChain.doFilter(request, response);
            return;
        }

        if (jwtUtil.isExpired(token)) {
            log.info("token expired");
            response.sendRedirect("/login?error=expired");
            return;
        }

        UserEntity userEntity = createUserEntityFromToken(token);
        PrincipalUser principalUser = new PrincipalUser(userEntity);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(principalUser, null, principalUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookies(Cookie[] cookies) {
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private UserEntity createUserEntityFromToken(String token) {
        UserEntity userEntity = new UserEntity();
        userEntity.setNickname(jwtUtil.getNickname(token));
        userEntity.setUsername(jwtUtil.getUsername(token));
        userEntity.setRole(jwtUtil.getRole(token));
        userEntity.setProvider(jwtUtil.getProvider(token));
        userEntity.setProviderId(jwtUtil.getProviderId(token));
        return userEntity;
    }
}

/**
 * [스프링 시큐리티 JWT]
 * UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
 * > 스프링 시큐리티 인증 토큰 생성
 * SecurityContextHolder.getContext().setAuthentication(authToken);
 * > 세션에 사용자 등록
 * > 세션은 stateless 상태로 관리되기 때문에 해당 요청이 끝나면 소멸한다.
 *
 * userEntity.setPassword("temppassword");
 * > DB에 비밀번호 조회도, 비밀번호 검증도 하지 않음.
 * -> 이미 JWT 자체가 신뢰된 인증 수단이기 때문.
 *
 * ---
 * 로그인 필터 메모
 * /** = 일반 로그인 흐름 =
 *  * LoginFilter 가 authenticationManager 를 호출하여 검증을 실행한다.
 *  * 성공 시 successfulAuthentication, 실패 시 unsuccessfulAuthentication
 *  *
 *  * 클라이언트가 아이디/비밀번호를 서버에 보냄 → LoginFilter가 이를 가로채서 인증 시도(attemptAuthentication)
 *  * AuthenticationManager가 UserDetailsService에서 CustomUserDetails를 불러와 인증 처리
 *  * 인증 성공 시 successfulAuthentication에서 JWT 토큰 생성 → 응답 헤더에 JWT 전달 (혹은 쿠키)
 *  * 클라이언트가 JWT를 저장 (로컬스토리지, 쿠키 등)
 *  * 클라이언트가 이후 요청 시 JWT를 헤더(예: Authorization: Bearer {token})에 포함해 서버에 보냄
 *  * 서버는 JWT를 JwtFilter 같은 필터에서 검증 → 토큰 유효하면 SecurityContext에 인증 객체 설정 → 요청 정상 처리
 *  *
 *  * response.addHeader("Authorization", "Bearer " + token);
 *  * > HTTP 인증 방식은 RFC 7235 정의에 따라 인증 헤더 형태를 띄어야 하므로
 *  * > ex. Authorization: Bearer {인증토큰String}
 *
 *
 */
