//package com.rookie.bigdata.handler;
//
//
//import com.rookie.bigdata.controller.HelloController;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//
//
//import java.io.IOException;
//
//
///**
// * @Classname CustomAuthenticationSuccessHandler
// * @Description 认证成功处理器 参考SavedRequestAwareAuthenticationSuccessHandler
// * @Author rookie
// * @Date 2023/3/9 17:16
// * @Version 1.0
// */
//@Component
//public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
//
//    public static final Logger logger = LoggerFactory.getLogger(HelloController.class);
//
//    private  RequestCache requestCache = new HttpSessionRequestCache();
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {	SavedRequest savedRequest = this.requestCache.getRequest(request, response);
//        if (savedRequest == null) {
//            super.onAuthenticationSuccess(request, response, authentication);
//            return;
//        }
//        String targetUrlParameter = getTargetUrlParameter();
//        if (isAlwaysUseDefaultTargetUrl()
//                || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
//            this.requestCache.removeRequest(request, response);
//            super.onAuthenticationSuccess(request, response, authentication);
//            return;
//        }
//        clearAuthenticationAttributes(request);
//        // Use the DefaultSavedRequest URL
//        String targetUrl = savedRequest.getRedirectUrl();
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);
//    }
//
//    public void setRequestCache(RequestCache requestCache) {
//        this.requestCache = requestCache;
//    }
//
//}
