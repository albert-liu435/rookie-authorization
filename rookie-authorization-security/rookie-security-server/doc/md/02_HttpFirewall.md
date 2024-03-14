## HttpFirewall使用 

默认为使用的 是StrictHttpFirewall，可以在org.springframework.security.web.FilterChainProxy查看。

如果要更改，则直接加入bean交由Spring管理即可。如：

```java
    @Bean
    HttpFirewall httpFirewall() {
        return new DefaultHttpFirewall();
    }
```

最终会在org.springframework.security.config.annotation.web.builders.WebSecurity中的

 setApplicationContext(ApplicationContext applicationContext) 在从Spring容器中获取并重新进行设置

在请求过程中会通过 org.springframework.security.web.FilterChainProxy中的doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) 对请求进行拦截和处理，如设置白名单IP等





参考文档：

[SpringSecurity(十六)：HttpFirewall ](https://www.cnblogs.com/wangstudyblog/p/14806994.html)

[spring-security使用-安全防护HttpFirewall(七)](https://www.cnblogs.com/LQBlog/p/14343497.html)