package com.rookie.bigdata.security.access;

import com.rookie.bigdata.util.ResponseUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;


import java.io.IOException;

/**
 * @Classname CustomAccessDeniedHandler
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:12
 * @Version 1.0
 */
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {

        if (accessDeniedException instanceof MissingCsrfTokenException) {
            ResponseUtils.forbiddenResponse(response, "Require csrf-token.");
        }

        if (accessDeniedException instanceof InvalidCsrfTokenException) {
            ResponseUtils.forbiddenResponse(response, "Invalid csrf-token.");
            return;
        }

        ResponseUtils.forbiddenResponse(response, accessDeniedException.getMessage());
    }

}
