package com.rookie.bigdata.security.filter;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @Classname HttpServletRequestWrapFilter
 * @Description 请求包装类，这样可以多次获取请求的参数
 * @Author rookie
 * @Date 2023/3/8 9:40
 * @Version 1.0
 */

public class HttpServletRequestWrapFilter extends OncePerRequestFilter {

    public static final Logger logger = LoggerFactory.getLogger(HttpServletRequestWrapFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.info("request body servlet request wrap filter ...");
        final RequestBodyServletRequestWrapper requestWrapper = new RequestBodyServletRequestWrapper(request);
        filterChain.doFilter(requestWrapper, response);
    }


    private static class RequestBodyServletRequestWrapper extends HttpServletRequestWrapper {

        /**
         * 请求体数据
         */
        private final byte[] requestBody;
        /**
         * 重写的参数 Map
         */
        private final Map<String, String[]> paramMap;

        public RequestBodyServletRequestWrapper(HttpServletRequest request) throws IOException {
            super(request);

            // 重写 requestBody
            requestBody = IOUtils.toByteArray(request.getReader(), StandardCharsets.UTF_8);

            // 重写参数 Map
            paramMap = new HashMap<>();

            if (requestBody.length == 0) {
                return;
            }

            JSON.parseObject(getRequestBody()).forEach((key, value) -> paramMap.put(key, new String[]{String.valueOf(value)}));
        }

        public String getRequestBody() {

            return new String(requestBody, StandardCharsets.UTF_8);
//            return StringUtils.toEncodedString(requestBody, StandardCharsets.UTF_8);
        }

        // ~ get
        // -----------------------------------------------------------------------------------------------------------------

        @Override
        public Map<String, String[]> getParameterMap() {
            return paramMap;
        }

        @Override
        public String getParameter(String key) {
            String[] valueArr = paramMap.get(key);
            if (valueArr == null || valueArr.length == 0) {
                return null;
            }
            return valueArr[0];
        }

        @Override
        public String[] getParameterValues(String key) {
            return paramMap.get(key);
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(paramMap.keySet());
        }

        // ~ read
        // -----------------------------------------------------------------------------------------------------------------

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream()));
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return false;
                }

                @Override
                public boolean isReady() {
                    return false;
                }

                @Override
                public void setReadListener(ReadListener listener) {

                }

                @Override
                public int read() {
                    return inputStream.read();
                }
            };
        }
    }
}
