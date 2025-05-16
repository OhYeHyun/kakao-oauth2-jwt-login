package hello.kakao_oauth2_jwt_login.service;

import hello.kakao_oauth2_jwt_login.dto.JoinDto;
import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import hello.kakao_oauth2_jwt_login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDto joinDto) {

        // 중복하는지 확인 로직 추가

        UserEntity user = new UserEntity();
        user.setUsername(joinDto.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        user.setRole("ROLE_USER");

        userRepository.save(user);
    }
}

/**
 *  내부적으로 ROLE_ADMIN 처럼 찾기 때문에, 권한 부여할 때 "ROLE_" prefix를 포함해야 합니다.
 */
