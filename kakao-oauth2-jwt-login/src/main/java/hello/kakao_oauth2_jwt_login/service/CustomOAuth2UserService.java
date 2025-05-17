package hello.kakao_oauth2_jwt_login.service;

import hello.kakao_oauth2_jwt_login.dto.CustomOAuth2User;
import hello.kakao_oauth2_jwt_login.dto.KakaoResponse;
import hello.kakao_oauth2_jwt_login.dto.OAuth2Response;
import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import hello.kakao_oauth2_jwt_login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;
        if (registrationId.equals("kakao")) {
            oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        String nickname = oAuth2Response.getNickname();
        UserEntity userData = userRepository.findByUsername(username);

        String role = "ROLE_USER";
        if (userData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setNickname(nickname);
            userEntity.setRole(role);

            userRepository.save(userEntity);
        } else {
            role = userData.getRole();
            userData.setNickname(nickname);
        }

        return new CustomOAuth2User(oAuth2Response, role);
    }
}

/**
 * [사용자 카카오 로그인 클릭]
 *        ↓
 * [Spring Security가 Kakao에 요청 → 콜백 처리]
 *        ↓
 * [CustomOAuth2UserService.loadUser() 실행됨]
 *        ↓
 * [KakaoResponse로 파싱]
 *        ↓
 * [UserEntity 조회/생성 → DB 저장]
 *        ↓
 * [CustomOAuth2User 반환 → Security Context에 저장]
 */
