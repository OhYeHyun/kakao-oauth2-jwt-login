package hello.kakao_oauth2_jwt_login.service;

import hello.kakao_oauth2_jwt_login.dto.*;
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
        OAuth2Response oAuth2Response = extractOAuth2Response(registrationId, oAuth2User);
        if (oAuth2Response == null) return null;

        String username = buildUsername(oAuth2Response);
        UserEntity userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            userEntity = createUserEntityFromOAuth2Response(oAuth2Response);
        } else {
            updateUserEntity(userEntity, oAuth2Response);
        }

        return new PrincipalUser(userEntity);
    }

    private OAuth2Response extractOAuth2Response(String registrationId, OAuth2User oAuth2User) {
        if (registrationId.equals("kakao")) {
            return new KakaoResponse(oAuth2User.getAttributes());
        }
        return null;
    }

    private UserEntity createUserEntityFromOAuth2Response(OAuth2Response oAuth2Response) {
        UserEntity userEntity = new UserEntity();

        userEntity.setNickname(oAuth2Response.getNickname());
        userEntity.setUsername(buildUsername(oAuth2Response));
        userEntity.setRole("ROLE_USER");
        userEntity.setProvider(oAuth2Response.getProvider());
        userEntity.setProviderId(oAuth2Response.getProviderId());

        return userRepository.save(userEntity);
    }

    private String buildUsername(OAuth2Response oAuth2Response) {
        return oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
    }

    private void updateUserEntity(UserEntity userEntity, OAuth2Response response) {
        userEntity.setNickname(response.getNickname());
        userEntity.setProvider(response.getProvider());
        userEntity.setProviderId(response.getProviderId());
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
