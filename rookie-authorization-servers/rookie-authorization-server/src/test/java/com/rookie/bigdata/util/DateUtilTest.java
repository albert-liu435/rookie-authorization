package com.rookie.bigdata.util;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @Class DateUtilTest
 * @Description
 * @Author rookie
 * @Date 2024/3/21 11:29
 * @Version 1.0
 */
class DateUtilTest {

    public static final Logger logger = LoggerFactory.getLogger(DateUtilTest.class);

    @Test
    void test01(){
        Date startDate = DateUtil.stringToDate("2024-03-21 11:11:11");

        logger.info("date: {}",startDate);

    }

    @Test
    void test02(){
        String s = UUID.randomUUID().toString();

        logger.info("uuid: {}",s);
    }

}
