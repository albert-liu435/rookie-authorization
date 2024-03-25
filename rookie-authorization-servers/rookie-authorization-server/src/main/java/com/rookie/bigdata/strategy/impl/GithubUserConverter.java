package com.rookie.bigdata.strategy.impl;


import com.rookie.bigdata.entity.Oauth2ThirdAccount;
import com.rookie.bigdata.strategy.Oauth2UserConverterStrategy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;


/**
 * 转换通过Github登录的用户信息
 *
 * @author vains
 */
@Component(GithubUserConverter.LOGIN_TYPE)
public class GithubUserConverter implements Oauth2UserConverterStrategy {

    protected static final String LOGIN_TYPE = "github";

    @Override
    public Oauth2ThirdAccount convert(OAuth2User oAuth2User) {
        // TODO 映射GitHub的用户信息
        System.out.println(oAuth2User.getAttributes());
        return null;
    }
}
