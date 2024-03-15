package com.rookie.bigdata.security.access;

import com.rookie.bigdata.domain.dto.RoleMenuDto;
import com.rookie.bigdata.mapper.RoleMapper;
import com.rookie.bigdata.security.csrf.CsrfTokenRedisRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @Classname DynamicFilterInvocationSecurityMetadataSource
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:56
 * @Version 1.0
 */
@Component
public class DynamicFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    public static final Logger logger = LoggerFactory.getLogger(CsrfTokenRedisRepository.class);


    private static final String CLASS_NAME = "Dynamic filter invocation security metadata source";

    @Autowired
    private RoleMapper roleMapper;

    @Autowired
    private AntPathMatcher antPathMatcher;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // 因为 supports 方法只放行了 FilterInvocation 和其父类以及接口, 所以
        // 总是 dynamic filter invocation security metadata source, getAttributes: org.springframework.security.web.FilterInvocation
        // log.debug("{}#getAttributes: {}", CLASS_NAME, object.getClass().getCanonicalName());

        FilterInvocation filterInvocation = (FilterInvocation) object;
        // http://localhost:18903/dynamic-authorization/user/1 的 /user/1
        final String requestUrl = filterInvocation.getRequestUrl();
        logger.debug("{}#getAttributes: {}", CLASS_NAME, requestUrl);

        // 查询数据库获取角色和权限的对应关系
        //  这个对应关系应该放到缓存中. 如果有更改的需要, 可以在前端提供一个操作手动重新加载权限对应关系
        final List<RoleMenuDto> roleMenuDtos = roleMapper.queryRoleMenuDto();
        final String[] matchedRoles = roleMenuDtos.stream()
                .filter(roleMenuDto -> antPathMatcher.match(roleMenuDto.getRequestUrl(), requestUrl))
                .map(RoleMenuDto::getRoleName).collect(Collectors.toSet()).toArray(new String[]{});

        // 如果返回 null 或者 空集合, 不会调用 AccessDecisionManager 的 decide 方法,
        // ref AbstractSecurityInterceptor 199 行
        if (matchedRoles.length > 0) {
            return SecurityConfig.createList(matchedRoles);
        }

        // 如果当前请求的 URL 没有在 角色-权限对应关系中存在, 则表示匿名用户也可访问
        logger.debug("{}#getAttributes :: anonymous user.", CLASS_NAME);
        return SecurityConfig.createList("ROLE_ANONYMOUS");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        logger.debug("{}#getAllConfigAttributes", CLASS_NAME);
        //  这个对应关系应该放到缓存中. 如果有更改的需要, 可以在前端提供一个操作手动重新加载权限对应关系
        return SecurityConfig.createList(
                roleMapper.queryRoleMenuDto().stream()
                        .map(RoleMenuDto::getRoleName).collect(Collectors.toSet()).toArray(new String[]{})
        );
    }

    @Override
    public boolean supports(Class<?> clazz) {
        logger.debug("{}#supports: {}", CLASS_NAME, clazz.getCanonicalName());
        return FilterInvocation.class.isAssignableFrom(clazz);
    }


}
