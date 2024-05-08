package com.rookie.bigdata.authorization.web;

import com.rookie.bigdata.util.JsonUtils;
import com.rookie.bigdata.util.SecurityUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Map;

/**
 * @Author rookie
 * @Description 自定义AuthenticationEntryPoint处理
 * @Date 2024/5/8 21:29
 * @Version 1.0
 */
public class CustomerAuthenticationEntryPoint implements AuthenticationEntryPoint {

    protected final Logger logger = LoggerFactory.getLogger(CustomerAuthenticationEntryPoint.class);


    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Map<String, String> parameters = SecurityUtils.getErrorParameter(request, response, authException);
        String wwwAuthenticate = SecurityUtils.computeWwwAuthenticateHeaderValue(parameters);
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(JsonUtils.objectCovertToJson(parameters));
            response.getWriter().flush();
        } catch (IOException ex) {
            logger.error("写回错误信息失败", authException);
        }
    }
}