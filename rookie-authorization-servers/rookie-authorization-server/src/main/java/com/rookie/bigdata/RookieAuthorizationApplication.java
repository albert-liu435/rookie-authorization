package com.rookie.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

@EnableScheduling
@SpringBootApplication
public class RookieAuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(RookieAuthorizationApplication.class, args);
    }

}
