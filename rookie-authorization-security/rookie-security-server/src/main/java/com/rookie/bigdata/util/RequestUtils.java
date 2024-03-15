package com.rookie.bigdata.util;

import com.rookie.bigdata.config.ApplicationConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;


/**
 * @Classname RequestUtils
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:47
 * @Version 1.0
 */
public final class RequestUtils {

    private RequestUtils() {
    }

    /**
     * Description: 获得有效的 requestURI
     */
    public static String getQualifiedURI(HttpServletRequest request) {
        return StringUtils.replace(request.getRequestURI(), ApplicationConfiguration.CONTEXT_PATH, "");
    }
}
