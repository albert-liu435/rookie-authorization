package com.rookie.bigdata.service.impl;


import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.rookie.bigdata.entity.Oauth2ThirdAccount;
import com.rookie.bigdata.mapper.Oauth2ThirdAccountMapper;
import com.rookie.bigdata.service.IOauth2ThirdAccountService;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 三方登录账户信息表 服务实现类
 * </p>
 *
 * @author vains
 * @since 2023-07-04
 */
@Service
public class Oauth2ThirdAccountServiceImpl extends ServiceImpl<Oauth2ThirdAccountMapper, Oauth2ThirdAccount> implements IOauth2ThirdAccountService {

}
