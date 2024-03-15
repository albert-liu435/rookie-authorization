package com.rookie.bigdata.domain;

import lombok.Builder;
import lombok.Data;

/**
 * @Classname RedisKey
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:48
 * @Version 1.0
 */
@Data
@Builder
public final class RedisKey {

    public static final String SEPARATOR = ".";

    /**
     * Redis key 的前缀
     */
    private String prefix;

    /**
     * Redis key 的内容
     */
    private String suffix;

    public String of() {
        return String.format("%s.%s", prefix, suffix);
    }
}
