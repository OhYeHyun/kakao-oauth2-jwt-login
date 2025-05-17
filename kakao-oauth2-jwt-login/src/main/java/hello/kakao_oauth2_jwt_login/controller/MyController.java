package hello.kakao_oauth2_jwt_login.controller;

import hello.kakao_oauth2_jwt_login.dto.CustomOAuth2User;
import hello.kakao_oauth2_jwt_login.dto.CustomUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MyController {

    @GetMapping("/my")
    public String myP(@AuthenticationPrincipal Object principal, Model model) {
        System.out.println("Authentication principal = " + principal);
        System.out.println("Principal class = " + (principal != null ? principal.getClass() : "null"));

        if (principal instanceof CustomUserDetails) {
            String nickname = ((CustomUserDetails) principal).getNickname();
            model.addAttribute("nickname", nickname);
        }

        if (principal instanceof CustomOAuth2User) {
            String nickname = ((CustomOAuth2User) principal).getName();
            model.addAttribute("nickname", nickname);
        }
        return "my";
    }
}
