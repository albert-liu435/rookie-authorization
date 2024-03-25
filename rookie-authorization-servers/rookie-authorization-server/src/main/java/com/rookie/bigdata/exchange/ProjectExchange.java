package com.rookie.bigdata.exchange;

/**
 * @Author rookie
 * @Description TODO
 * @Date 2024/3/25 22:55
 * @Version 1.0
 */

import com.rookie.bigdata.model.Result;
import com.rookie.bigdata.model.response.CaptchaResult;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/**
 * 为back4app部署准备的接口，调用当前服务
 *
 * @author vains
 */
@HttpExchange
public interface ProjectExchange {

    /**
     * 调用当前项目的获取验证码方法
     *
     * @return 统一响应类
     */
    @GetExchange("/getCaptcha")
    Result<CaptchaResult> getCaptcha();

}