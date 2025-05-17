package hello.kakao_oauth2_jwt_login.controller;

import hello.kakao_oauth2_jwt_login.dto.JoinDto;
import hello.kakao_oauth2_jwt_login.service.JoinService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String joinP(Model model) {
        model.addAttribute("joinDto", new JoinDto());
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(@Valid @ModelAttribute JoinDto joinDto, BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            log.info("오류 발생: {}", bindingResult);
            return "join";
        }

        try {
            joinService.joinProcess(joinDto);
            return "/login";

        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("아이디")) {
                bindingResult.rejectValue("username", "error.username", e.getMessage());
            }
            if (e.getMessage().contains("비밀번호")) {
                bindingResult.rejectValue("password", "error.password", e.getMessage());
            }
            return "join";
        }
    }
}
