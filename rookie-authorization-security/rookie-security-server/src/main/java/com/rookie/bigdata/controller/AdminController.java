package com.rookie.bigdata.controller;

import com.alibaba.fastjson2.JSON;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Classname AdminController
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:13
 * @Version 1.0
 */
@RequestMapping("/admin")
@RestController
public class AdminController {


    @GetMapping("/info")
    public String info() {

        return JSON.toJSONString(SecurityContextHolder.getContext().getAuthentication());
    }

}
