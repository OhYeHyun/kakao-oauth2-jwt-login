package hello.kakao_oauth2_jwt_login.dto;

import lombok.Data;

@Data
public class UserDto {

    private String nickname;
    private String username;
    private String role;
}
