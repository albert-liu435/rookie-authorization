package com.rookie.bigdata.controller;

import com.alibaba.fastjson2.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @Classname AuthController
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:13
 * @Version 1.0
 */
@RequestMapping("/auth")
@RestController
public class AuthController {

    public static final Logger logger = LoggerFactory.getLogger(HelloController.class);


    private static final String CLASS_NAME = "AuthController";

    @PostMapping("/register")
    public void register(@RequestBody Map<String, String> userInfo) {
        logger.debug("{}#register :: 用户注册接口, 用户信息: {}", CLASS_NAME, JSON.toJSONString(userInfo));
    }

}
