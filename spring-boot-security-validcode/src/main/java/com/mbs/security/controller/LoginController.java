package com.mbs.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 类功能描述：
 *
 * @author：yandehong
 * @createTime：2020/11/24 17:31
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/getAuthentication")
    @ResponseBody
    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @GetMapping("/getAuthentication2")
    @ResponseBody
    public Authentication getAuthentication(Authentication authentication) {
        return authentication;
    }
}
