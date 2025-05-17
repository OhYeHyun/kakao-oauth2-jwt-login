package hello.kakao_oauth2_jwt_login.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getNickname(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("nickname", String.class);
    }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public String getProvider(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("provider", String.class);
    }

    public String getProviderId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("providerId", String.class);
    }

    public Boolean isExpired(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public String createJwt(String nickname, String username, String role, String provider, String providerId, Long expiredMs) {
        return Jwts.builder()
                .claim("nickname", nickname)
                .claim("username", username)
                .claim("role", role)
                .claim("provider", provider)
                .claim("providerId", providerId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}

/**
 * application.properties 에 지정한 ${spring.jwt.secret} 값으로 secretKey 를 생성
 * Jwts.parser().verifyWith(secretKey) : 토큰이 우리 서버에서 생성되었는지, 우리 서버에서 생성된 키가 가진 키와 맞는지 확인
 *
 * .issuedAt(new Date(System.currentTimeMillis()))
 * > 발급 시각, issuedAt)가 포함되어 있기 때문에, 매번 현재 시간을 기준으로 발급되면 내용이 달라지므로,각 요청마다 클라이언트가 보내야 한다.
 */