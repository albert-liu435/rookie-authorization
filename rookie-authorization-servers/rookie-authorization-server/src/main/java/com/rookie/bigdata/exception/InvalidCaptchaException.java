package com.rookie.bigdata.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @Class InvalidCaptchaException
 * @Description 验证码异常类 校验验证码异常时抛出
 * @Author rookie
 * @Date 2024/3/22 13:24
 * @Version 1.0
 */

public class InvalidCaptchaException extends AuthenticationException {

    public InvalidCaptchaException(String msg) {
        super(msg);
    }

}

