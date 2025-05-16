package hello.kakao_oauth2_jwt_login.dto;

import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class KakaoResponse implements OAuth2Response {

    private final Map<String, Object> attribute;

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getNickname() {
        Map<String, Object> props = (Map<String, Object>) attribute.get("properties");
        if (props != null && props.get("nickname") != null) {
            return props.get("nickname").toString();
        }

        Map<String, Object> account = (Map<String, Object>) attribute.get("kakao_account");
        if (account != null) {
            Map<String, Object> profile = (Map<String, Object>) account.get("profile");
            if (profile != null) {
                return profile.getOrDefault("nickname", "").toString();
            }
        }
        return "";
    }
}
