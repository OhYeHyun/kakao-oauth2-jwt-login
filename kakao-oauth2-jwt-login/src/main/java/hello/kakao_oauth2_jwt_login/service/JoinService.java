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
        validateDto(joinDto);

        UserEntity user = new UserEntity();
        user.setNickname(joinDto.getNickname());
        user.setUsername(joinDto.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        user.setRole("ROLE_USER");

        userRepository.save(user);
    }

    private void validateDto(JoinDto joinDto) {
        isDuplicatedUsername(joinDto.getUsername());
        validateFormatUsername(joinDto.getUsername());
        validateFormatPassword(joinDto.getPassword());
    }

    private void isDuplicatedUsername(String username) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("이미 존재하는 아이디입니다.");
        }
    }

    private void validateFormatUsername(String username) {
        if (!username.matches("^[a-zA-Z0-9]+$")) {
            throw new IllegalArgumentException("아이디에는 특수문자를 사용할 수 없습니다.");
        }

        if (username.toLowerCase().contains("admin")) {
            throw new IllegalArgumentException("'admin'은 아이디로 사용할 수 없습니다.");
        }

        if (username.toLowerCase().startsWith("kakao")) {
            throw new IllegalArgumentException("사용할 수 없는 아이디입니다.");
        }
    }

    private void validateFormatPassword(String password) {
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            throw new IllegalArgumentException("비밀번호에는 최소 하나 이상의 특수문자가 포함되어야 합니다.");
        }
    }
}
