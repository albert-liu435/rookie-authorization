//package com.rookie.bigdata.handler;
//
//import com.rookie.bigdata.controller.HelloController;
//import jakarta.servlet.ServletOutputStream;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.stereotype.Component;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//
///**
// * @Classname AuthenticationFailureHandler
// * @Description 自定义认证失败处理器
// * @Author rookie
// * @Date 2023/3/9 17:09
// * @Version 1.0
// */
//@Component
//public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
//
//    public static final Logger logger = LoggerFactory.getLogger(HelloController.class);
//
//
//    /**
//     * 认证失败后的处理逻辑,可以参考SimpleUrlAuthenticationFailureHandler进行编写
//     *
//     * @param request
//     * @param response
//     * @param exception
//     * @throws IOException
//     * @throws ServletException
//     */
//    @Override
//    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//
//        logger.info("认证失败");
//        response.setContentType("application/json;charset=utf-8");
//        ServletOutputStream outputStream = response.getOutputStream();
//        outputStream.write("认证失败".getBytes(StandardCharsets.UTF_8));
//        outputStream.flush();
//
//
//    }
//}
