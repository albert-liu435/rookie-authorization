package com.rookie.bigdata.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @Author rookie
 * @Description 为了打印出过滤器日志
 * @Date 2024/4/9 0:12
 * @Version 1.0
 */
@EnableWebSecurity(debug = true)
@Configuration
public class ClientConfig {


}
