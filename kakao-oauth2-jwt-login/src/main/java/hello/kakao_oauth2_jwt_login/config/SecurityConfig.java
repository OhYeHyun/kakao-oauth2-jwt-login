package hello.kakao_oauth2_jwt_login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );

        http
                .csrf((auth) -> auth.disable());

        return http.build();
    }
}

/**
 * 인가 설정 :
 *   - "/" 및 "/login" 경로는 모두에게 허용 (permitAll)
 *   - "/admin" 경로는 ADMIN 권한을 가진 사용자만 접근 가능
 *   - 그 외 모든 요청은 인증된 사용자만 접근 가능 (authenticated)
 *
 * 커스텀 로그인 설정 :
 *   - 로그인 페이지: /login
 *   - 로그인 처리 URL: /loginProc (form 태그의 action으로 사용됨)
 *
 * CSRF 보호 :
 *   - 기본적으로 로그인 할 때 CSRF 토큰이 필요하지만, 개발 환경에서는 csrf 을 비활성화
 */
