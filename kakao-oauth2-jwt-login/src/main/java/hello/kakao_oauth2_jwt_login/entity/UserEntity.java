package hello.kakao_oauth2_jwt_login.entity;

import jakarta.persistence.*;
import lombok.Data;


@Entity
@Data
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String nickname;

    @Column(unique = true)
    private String username;

    private String password;
    private String role;
}
