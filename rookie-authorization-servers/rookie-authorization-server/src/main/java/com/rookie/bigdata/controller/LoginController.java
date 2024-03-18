package com.rookie.bigdata.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ShearCaptcha;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Class LoginController
 * @Description
 * @Author rookie
 * @Date 2024/3/18 17:51
 * @Version 1.0
 */
@RestController
@RequiredArgsConstructor
public class LoginController {

    @ResponseBody
    @GetMapping("/getCaptcha")
    public Map<String,Object> getCaptcha(HttpSession session) {
        // 使用hutool-captcha生成图形验证码
        // 定义图形验证码的长、宽、验证码字符数、干扰线宽度
        ShearCaptcha captcha = CaptchaUtil.createShearCaptcha(150, 40, 4, 2);
        // 这里应该返回一个统一响应类，暂时使用map代替
        Map<String,Object> result = new HashMap<>();
        result.put("code", HttpStatus.OK.value());
        result.put("success", true);
        result.put("message", "获取验证码成功.");
        result.put("data", captcha.getImageBase64Data());
        // 存入session中
        session.setAttribute("captcha", captcha.getCode());
        return result;
    }


}
