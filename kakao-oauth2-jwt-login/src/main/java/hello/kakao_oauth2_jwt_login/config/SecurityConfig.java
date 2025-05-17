package hello.kakao_oauth2_jwt_login.config;

import hello.kakao_oauth2_jwt_login.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf((auth) -> auth.disable());

        http
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/oauth2/**", "/image/**", "/login", "/loginProc", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );

        http
                .oauth2Login((oauth2) -> oauth2
                        .loginPage("/login")
                        .userInfoEndpoint((userInfoEndpointConfig) ->
                                userInfoEndpointConfig.userService(customOAuth2UserService)));

        return http.build();
    }
}

/**
 * [Spring Security]
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
 *
 *  ------
 * [JWT]
 * disable
 *   - csrf: JWT 에서는 stateless 로 관리하기 때문에 굳이 필요없음
 *   - formLogin, httpBasic: JWT 방식으로 진행할 것이기 때문에 필요없음
 *     formLogin 을 disable 했기 때문에, UsernamePasswordAuthenticationFilter 와 AuthenticationManager 를 구현해야 로그인 처리를 할 수 있다.
 *
 * STATELESS: JWT 를 통한 인가/인증을 위해 STATELESS 로 설정
 *
 * ---
 * [OAuth2 세션]
 * userInfoEndpoint().userService(...)
 * -  OAuth2 로그인 시 OAuth2 제공자(Kakao)에서 받은 유저 정보로부터 인증 객체를 만들도록 도와주는 서비스
 *
 * 시큐리티 로그인: UsernamePasswordAuthenticationToken 생성 시 DB에서 직접 유저 정보를 조회.
 * OAuth2 로그인: 제공자에서 유저 정보 API로 조회한 데이터를 사용해서 조회
 */
