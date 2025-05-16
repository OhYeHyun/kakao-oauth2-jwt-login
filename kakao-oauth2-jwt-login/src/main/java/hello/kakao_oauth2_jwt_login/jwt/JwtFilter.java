package hello.kakao_oauth2_jwt_login.jwt;

import hello.kakao_oauth2_jwt_login.dto.CustomUserDetails;
import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
        String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.info("token null");
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.split(" ")[1];
        if (jwtUtil.isExpired(token)) {
            log.info("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}

/**
 * UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
 * > 스프링 시큐리티 인증 토큰 생성
 * SecurityContextHolder.getContext().setAuthentication(authToken);
 * > 세션에 사용자 등록
 * > 세션은 stateless 상태로 관리되기 때문에 해당 요청이 끝나면 소멸한다.
 *
 * userEntity.setPassword("temppassword");
 * > DB에 비밀번호 조회도, 비밀번호 검증도 하지 않음.
 * -> 이미 JWT 자체가 신뢰된 인증 수단이기 때문.
 */
