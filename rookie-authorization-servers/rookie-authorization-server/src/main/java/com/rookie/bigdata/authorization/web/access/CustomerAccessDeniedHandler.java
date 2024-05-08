package com.rookie.bigdata.authorization.web.access;

import com.rookie.bigdata.util.JsonUtils;
import com.rookie.bigdata.util.SecurityUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.Map;

/**
 * @Author rookie
 * @Description 自定义权限不足处理
 * @Date 2024/5/8 21:41
 * @Version 1.0
 */
public class CustomerAccessDeniedHandler implements AccessDeniedHandler {
    protected final Logger logger = LoggerFactory.getLogger(CustomerAccessDeniedHandler.class);



    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Map<String, String> parameters = SecurityUtils.getErrorParameter(request, response, accessDeniedException);
        String wwwAuthenticate = SecurityUtils.computeWwwAuthenticateHeaderValue(parameters);
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(JsonUtils.objectCovertToJson(parameters));
            response.getWriter().flush();
        } catch (IOException ex) {
            logger.error("写回错误信息失败", accessDeniedException);
        }
    }
}
