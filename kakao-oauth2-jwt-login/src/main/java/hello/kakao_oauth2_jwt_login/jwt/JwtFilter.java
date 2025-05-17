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
