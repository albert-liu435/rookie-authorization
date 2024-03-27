package com.rookie.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

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
