package com.rookie.bigdata.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Classname UserController
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:14
 * @Version 1.0
 */
@RequestMapping("/user")
@RestController
public class UserController {

    @PostMapping("/{id}")
    public String get(@PathVariable String id) {
        return "UserController: " + id;
    }

}
