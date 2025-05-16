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
                        .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
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
 *   - "/" 및 "/login" 등 경로는 모두에게 허용 (permitAll)
 *   - "/admin" 경로는 ADMIN 권한을 가진 사용자만 접근 가능
 *   - 그 외 모든 요청은 인증된 사용자만 접근 가능 (authenticated)
 *
 * 커스텀 로그인 설정 :
 *   - 로그인 페이지: 인증이 필요한 페이지에 접근하면 "/login" 로 리다이렉트
 *   - 로그인 처리 URL: "/loginProc" 는 로그인 요청을 처리하는 엔드포인트
 *                    해당 URL 로 POST 요청이 오면, Spring Security 가 해당 요청을 가로채고 내부에서 로그인 처리를 해 준다.
 *                    이 때, UserDetailsService 와 UserDetails 를 구현해 두어야
 *                    UserDetailsService 로 사용자를 조회하고, 반환된 UserDetails 객체를 기반으로 인증 처리를 진행한다.
 *
 * CSRF 보호 :
 *   - 기본적으로 로그인 할 때 CSRF 토큰이 필요하지만, 개발 환경에서는 csrf 을 비활성화
 */
