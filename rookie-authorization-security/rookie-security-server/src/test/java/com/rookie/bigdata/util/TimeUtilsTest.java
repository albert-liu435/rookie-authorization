package com.rookie.bigdata.util;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;


/**
 * @Class TimeUtilsTest
 * @Description
 * @Author rookie
 * @Date 2024/3/15 17:50
 * @Version 1.0
 */
class TimeUtilsTest {

    //日志工具类
    protected static final Logger logger = LoggerFactory.getLogger(TimeUtilsTest.class);


    @Test
    void test01(){
        String format = DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN);
        logger.info("格式化：{}" ,format);

    }

}
