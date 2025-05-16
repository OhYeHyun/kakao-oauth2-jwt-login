package hello.kakao_oauth2_jwt_login.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class JoinDto {

    @NotBlank
    @Size(min = 5, message = "아이디는 최소 5자 이상이어야 합니다.")
    private String username;

    @NotBlank
    @Size(min = 9, message = "비밀번호는 최소 9자 이상이어야 합니다.")
    private String password;
}
