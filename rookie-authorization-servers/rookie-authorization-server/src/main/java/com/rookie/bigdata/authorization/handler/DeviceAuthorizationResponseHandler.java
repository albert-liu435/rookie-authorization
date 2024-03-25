package com.rookie.bigdata.authorization.handler;


import com.rookie.bigdata.model.Result;
import com.rookie.bigdata.util.JsonUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;


/**
 * 校验设备码成功响应类
 *
 * @author vains
 */
@RequiredArgsConstructor
public class DeviceAuthorizationResponseHandler implements AuthenticationSuccessHandler {

    private final String deviceActivatedUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // 写回json数据
        Result<Object> result = Result.success(deviceActivatedUri);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(JsonUtils.objectCovertToJson(result));
        response.getWriter().flush();
    }
}
