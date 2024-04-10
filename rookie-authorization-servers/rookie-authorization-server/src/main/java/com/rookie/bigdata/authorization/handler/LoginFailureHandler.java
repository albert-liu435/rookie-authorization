package com.rookie.bigdata.authorization.handler;


import com.rookie.bigdata.model.Result;
import com.rookie.bigdata.util.JsonUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;


/**
 * @Author rookie
 * @Description 登录失败处理类
 * @Date 2024/4/10 23:34
 * @Version 1.0
 */
public class LoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        // 登录失败，写回401与具体的异常
        Result<String> success = Result.error(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(JsonUtils.objectCovertToJson(success));
        response.getWriter().flush();
    }

}
