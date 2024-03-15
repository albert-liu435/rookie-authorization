//package com.rookie.bigdata.filter;
//
//
//import com.alibaba.fastjson2.JSON;
//import com.rookie.bigdata.domain.CustomUserDetails;
//import com.rookie.bigdata.domain.User;
//import com.rookie.bigdata.util.JWTUtils;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletInputStream;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.SneakyThrows;
//import lombok.extern.slf4j.Slf4j;
//import org.apache.commons.io.IOUtils;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//
///**
// * @Classname JWTAuthenticationFilter
// * @Description
// * @Author rookie
// * @Date 2023/3/10 11:28
// * @Version 1.0
// */
//@Slf4j
//public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//
//    private final AuthenticationManager authenticationManager;
//
//    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//    }
//
//    /**
//     * @param request
//     * @param response
//     * @return
//     * @throws AuthenticationException
//     */
//    @SneakyThrows
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//
//        ServletInputStream inputStream = request.getInputStream();
//        byte[] bytes = IOUtils.toByteArray(inputStream);
//        String str=new String(bytes);
//        log.info("获取的数据为：{}",str);
//
//        // 数据是通过 requestBody 传输
//        User user = JSON.parseObject(request.getInputStream(), StandardCharsets.UTF_8, User.class);
//
//        return authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(user.getName(), user.getPassword())
//        );
//    }
//
//    /**
//     * 认证成功之后调用该方法
//     *
//     * @param request
//     * @param response
//     * @param chain
//     * @param authResult
//     */
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                            FilterChain chain,
//                                            Authentication authResult) {
//        log.debug("authentication filter successful authentication: {}", authResult);
//
//        // 如果验证成功, 就生成 Token 并返回
//        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
//        response.setHeader("access-token",
//                JWTUtils.TOKEN_PREFIX + JWTUtils.create(customUserDetails.getName(), false, customUserDetails));
//    }
//
//    /**
//     * 如果 attemptAuthentication 抛出 AuthenticationException 则会调用这个方法
//     *
//     * @param request
//     * @param response
//     * @param failed
//     * @throws IOException
//     */
//    @Override
//    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                              AuthenticationException failed) throws IOException {
//        log.debug("authentication filter unsuccessful authentication: {}", failed.getMessage());
//        response.getWriter().write("authentication failed, reason: " + failed.getMessage());
//    }
//}
