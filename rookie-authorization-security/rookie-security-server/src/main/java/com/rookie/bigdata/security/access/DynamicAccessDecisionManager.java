package com.rookie.bigdata.security.access;


import com.alibaba.fastjson2.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @Classname DynamicAccessDecisionManager
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:54
 * @Version 1.0
 */
@Component
public class DynamicAccessDecisionManager implements AccessDecisionManager {


    public static final Logger logger = LoggerFactory.getLogger(DynamicAccessDecisionManager.class);


    private static final String CLASS_NAME = "Dynamic access decision manager";

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        // log.debug("{}#authentication: {}", CLASS_NAME, JSON.toJSONString(authentication));

        // In this case, object always be FilterInvocation
        // log.debug("{}#object: {}", CLASS_NAME, object.getClass().getCanonicalName());

        // 根据 requestUrl 过滤后的角色列表
        // log.debug("{}#configAttributes: {}", CLASS_NAME, JSON.toJSONString(configAttributes));

        final Set<String> requiredRolesByTargetResources = configAttributes.stream().map(ConfigAttribute::getAttribute).collect(Collectors.toSet());
        final Collection<? extends GrantedAuthority> incomingRequestAuthorities = authentication.getAuthorities();
        for (GrantedAuthority grantedAuthority : incomingRequestAuthorities) {
            // 如果当前 Authentication 有 requestUrl 的权限, 则认证通过
            //  用 AntPathMatcher 匹配C
            if (requiredRolesByTargetResources.contains(grantedAuthority.getAuthority())) {
                logger.debug("{}#decide :: authenticate success.", CLASS_NAME);
                return;
            }
        }

        //  需要查阅源码
        // 如果不执行 SecurityContextHolder.clearContext() 即使抛出 AccessDeniedException,
        // 最终 httpSecurity.exceptionHandling 也会捕获到 InsufficientAuthenticationException
        SecurityContextHolder.clearContext();
        throw new InsufficientAuthenticationException("权限不足");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        logger.debug("{}#supports {}", CLASS_NAME, JSON.toJSONString(clazz));
        return true;
    }
}
