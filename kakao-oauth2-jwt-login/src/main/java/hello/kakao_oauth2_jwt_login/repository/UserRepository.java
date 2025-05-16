package hello.kakao_oauth2_jwt_login.repository;

import hello.kakao_oauth2_jwt_login.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

}
