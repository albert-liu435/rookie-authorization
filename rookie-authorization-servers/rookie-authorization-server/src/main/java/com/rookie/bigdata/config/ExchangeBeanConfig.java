package com.rookie.bigdata.config;

/**
 * @Author rookie
 * @Description TODO
 * @Date 2024/3/25 22:55
 * @Version 1.0
 */

import com.rookie.bigdata.exchange.ProjectExchange;
import com.rookie.bigdata.property.CustomSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

/**
 * Http Interface注入ioc配置
 *
 * @author vains
 */
@Configuration
@RequiredArgsConstructor
public class ExchangeBeanConfig {

    private final CustomSecurityProperties securityProperties;

    /**
     * 注入MineExchange
     *
     * @return MineExchange
     */
    @Bean
    public ProjectExchange mineExchange() {
        WebClient webClient = WebClient.builder().baseUrl(securityProperties.getIssuerUrl()).build();
        HttpServiceProxyFactory httpServiceProxyFactory =
                HttpServiceProxyFactory.builder(WebClientAdapter.forClient(webClient))
                        .build();
        return httpServiceProxyFactory.createClient(ProjectExchange.class);
    }

}