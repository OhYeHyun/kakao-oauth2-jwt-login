package hello.kakao_oauth2_jwt_login.controller;

import hello.kakao_oauth2_jwt_login.dto.PrincipalUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MyController {

    @GetMapping("/my")
    public String myP(@AuthenticationPrincipal PrincipalUser principal, Model model) {
        String nickname = null;
        if (principal != null) {
            nickname = principal.getNickname();
        }
        model.addAttribute("nickname", nickname);

        return "my";
    }
}
