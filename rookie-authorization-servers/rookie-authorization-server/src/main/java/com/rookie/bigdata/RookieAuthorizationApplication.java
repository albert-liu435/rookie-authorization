package com.rookie.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * 应用启动类
 */
//@EnableScheduling
@SpringBootApplication
public class RookieAuthorizationApplication {

    public static void main(String[] args) {


        SpringApplication.run(RookieAuthorizationApplication.class, args);
    }

}
