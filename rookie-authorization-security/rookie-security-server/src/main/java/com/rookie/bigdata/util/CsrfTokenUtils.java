package com.rookie.bigdata.util;

import org.springframework.util.StringUtils;

import java.util.UUID;

/**
 * @Classname CsrfTokenUtils
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:42
 * @Version 1.0
 */
public final class CsrfTokenUtils {

    private CsrfTokenUtils() {
    }

    /**
     * Description: 生成 csrf-token
     *
     * @return java.lang.String csrf-token
     * @author LiKe
     * @date 2020-05-13 13:15:16
     */
    public static String create() {
        return StringUtils.replace(UUID.randomUUID().toString(), "-", "");
    }
}
