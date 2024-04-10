package com.rookie.bigdata.exception;

import org.springframework.security.core.AuthenticationException;
/**
 * @Author rookie
 * @Description 验证码异常类 校验验证码异常时抛出
 * @Date 2024/4/8 22:45
 * @Version 1.0
 */
public class InvalidCaptchaException extends AuthenticationException {

    public InvalidCaptchaException(String msg) {
        super(msg);
    }

}