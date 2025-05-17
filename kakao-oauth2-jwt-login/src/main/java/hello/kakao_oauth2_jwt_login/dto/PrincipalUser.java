package hello.kakao_oauth2_jwt_login.dto;

import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@RequiredArgsConstructor
public class PrincipalUser implements UserDetails, OAuth2User {

    private final UserEntity userEntity;

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword() != null ? userEntity.getPassword() : "";
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    public String getNickname() {
        return userEntity.getNickname();
    }

    // OAuth2
    @Override
    public String getName() {
        return getProvider() + " " + getProviderId();
    }

    public String getProvider() {
        return userEntity.getProvider();
    }

    public String getProviderId() {
        return userEntity.getProviderId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

/**
 * 계정이 잠기지 않고 계속 사용하도록 임의로 true 로 세팅
 * 구현은 DB Table 의 만료 유무를 체크하는 필드를 추가하여 구현
 */
