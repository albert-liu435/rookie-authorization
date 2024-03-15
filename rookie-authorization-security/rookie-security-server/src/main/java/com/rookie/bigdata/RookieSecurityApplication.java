package com.rookie.bigdata;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;


@MapperScan(basePackages = "com.rookie.bigdata.mapper")
@SpringBootApplication
public class RookieSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(RookieSecurityApplication.class, args);

    }

}
