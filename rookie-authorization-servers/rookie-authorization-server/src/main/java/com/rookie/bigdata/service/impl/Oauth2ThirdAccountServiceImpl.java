package com.rookie.bigdata.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.rookie.bigdata.entity.Oauth2ThirdAccount;
import com.rookie.bigdata.mapper.Oauth2ThirdAccountMapper;
import com.rookie.bigdata.service.IOauth2ThirdAccountService;
import org.springframework.stereotype.Service;

/**
 * @Author rookie
 * @Description 三方登录账户信息表 服务实现类
 * @Date 2024/4/9 23:21
 * @Version 1.0
 */
@Service
public class Oauth2ThirdAccountServiceImpl extends ServiceImpl<Oauth2ThirdAccountMapper, Oauth2ThirdAccount> implements IOauth2ThirdAccountService {

}
