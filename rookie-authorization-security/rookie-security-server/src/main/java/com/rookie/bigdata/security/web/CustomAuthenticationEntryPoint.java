package com.rookie.bigdata.security.web;

import com.rookie.bigdata.util.ResponseUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


import java.io.IOException;

/**
 * @Classname CustomAuthenticationEntryPoint
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:12
 * @Version 1.0
 */
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        ResponseUtils.unauthorizedResponse(response, authException.getMessage());
    }

}
