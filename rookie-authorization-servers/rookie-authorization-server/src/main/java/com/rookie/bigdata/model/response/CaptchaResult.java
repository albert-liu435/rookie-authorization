package com.rookie.bigdata.model.response;


import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @Class CaptchaResult
 * @Description 获取验证码返回
 * @Author rookie
 * @Date 2024/4/10 9:17
 * @Version 1.0
 */
@Data
@AllArgsConstructor
public class CaptchaResult {

    /**
     * 验证码id
     */
    private String captchaId;

    /**
     * 验证码的值
     */
    private String code;

    /**
     * 图片验证码的base64值
     */
    private String imageData;

}
