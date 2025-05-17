package hello.kakao_oauth2_jwt_login.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginP(@RequestParam(required = false) String error, Model model) {
        System.out.println(error);
        model.addAttribute("error", error);
        return "login";
    }
}
