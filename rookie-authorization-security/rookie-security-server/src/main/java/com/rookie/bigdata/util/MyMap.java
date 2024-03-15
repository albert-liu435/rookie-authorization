package com.rookie.bigdata.util;

import java.util.HashMap;
import java.util.Map;

/**
 * @Class MyMap
 * @Description
 * @Author rookie
 * @Date 2024/3/15 11:43
 * @Version 1.0
 */
public class MyMap {

    private Map<String, String> map = new HashMap<>();


    private MyMap() {
    };

    private static class SingletonHolder {
        /**
         * 静态初始化器，由JVM来保证线程安全
         */
        private static MyMap myMap = new MyMap();
    }

    //单例
    public static MyMap getMyMap() {
        return SingletonHolder.myMap;
    }

    public String put(String k, String v) {
        return map.put(k, v);
    }

    public String get(String k) {
        return map.get(k);
    }


}
