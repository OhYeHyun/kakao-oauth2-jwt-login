package hello.kakao_oauth2_jwt_login.controller;

import hello.kakao_oauth2_jwt_login.dto.JoinDto;
import hello.kakao_oauth2_jwt_login.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String joinP() {
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(JoinDto joinDto) {

        joinService.joinProcess(joinDto);

        return "redirect:/login";
    }
}
