//package com.rookie.bigdata.filter;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.web.csrf.CsrfToken;
//import org.springframework.security.web.csrf.CsrfTokenRepository;
//import org.springframework.security.web.csrf.DeferredCsrfToken;
//import org.springframework.stereotype.Service;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
///**
// * @Class CsrfHeaderFilter
// * @Description
// * @Author rookie
// * @Date 2024/3/15 15:45
// * @Version 1.0
// */
//
//@Slf4j
//
//@Service
//public   final class CsrfHeaderFilter extends OncePerRequestFilter {
//
//
//    @Autowired
//    private CsrfTokenRepository csrfTokenRepository;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
//        // Render the token value to a cookie by causing the deferred token to be loaded
//
////        if(csrfToken instanceof DeferredCsrfToken){
//            String token = csrfToken.getToken();
//            log.info("生成的token为：{} ",token);
////        }
//
//
//
//
//
//        //TODO 这里应该重新生成token并放入到header中
//        CsrfToken csrfToken1 = csrfTokenRepository.generateToken(request);
//
//        this.csrfTokenRepository.saveToken(csrfToken1, request, response);
//
//
////        request.setAttribute(HttpServletResponse.class.getName(), response);
////        CsrfToken csrfToken = this.tokenRepository.loadToken(request);
////        boolean missingToken = (csrfToken == null);
////        if (missingToken) {
////            csrfToken = this.tokenRepository.generateToken(request);
////            this.tokenRepository.saveToken(csrfToken, request, response);
////        }
////        request.setAttribute(CsrfToken.class.getName(), csrfToken);
////        request.setAttribute(csrfToken.getParameterName(), csrfToken);
//
//        filterChain.doFilter(request, response);
//    }
//
//}
