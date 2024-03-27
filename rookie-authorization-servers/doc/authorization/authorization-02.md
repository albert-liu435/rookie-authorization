# spring security 过滤器链结构图

![securityfilterchain](pic/authorization-02/multi-securityfilterchain.png)



WebSecurityConfiguration.springSecurityFilterChain()方法创建创建一个名称为springSecurityFilterChain的过滤器，过滤器对象为FilterChainProxy，里面封装了SecurityFilterChain对象，在进行http请求的时候，请求首先会到达DelegatingFilterProxy，然后通过获取targetBeanName名称的对象FilterChainProxy进行处理.
DelegatingFilterProxy对象的创建是在SecurityFilterAutoConfiguration.securityFilterChainRegistration(SecurityProperties securityProperties)中进行的,这个filter会加入到tomcat中进行，最终调用

# 过滤器

## DisableEncodeUrlFilter

这个过滤器有什么用？ 首先实现`Session`会话，可以通过以下两种方式

- **Cookie**：浏览器设置，每次请求自动携带给服务端
- **URL重写**：`Cookie`被禁用时，后端响应将`sessionId`拼接在`URL`后进行重写，传递给页面

`DisableEncodeUrlFilter`禁用`HttpServletResponse`对`URL`进行编码重写，以防止将`sessionId`在`HTTP`访问日志等内容中泄露。

## WebAsyncManagerIntegrationFilter

https://zhuanlan.zhihu.com/p/655746004

https://blog.csdn.net/liuyanglglg/article/details/104708317

## SecurityContextHolderFilter

SecurityContextConfigurer

获取安全上下文，默认程序启动的时候会加载，由SecurityContextConfigurer进行配置

默认采用的是DelegatingSecurityContextRepository委托类进行处理，里面存放RequestAttributeSecurityContextRepository和HttpSessionSecurityContextRepository。

SecurityContextHolderStrategy 持有安全上下文的策略接口

在每次请求到来时，FilterChain的前排有一个SecurityContextHolderFilter，负责调用SecurityContextRepository 获取context。

HttpSessionSecurityContextRepository ，NullSecurityContextRepository 和RequestAttributeSecurityContextRepository 都是SecurityContextRepository 的实现类。

HttpSessionSecurityContextRepository ：从session中获取context，保证同一个session用到的都是同一个context。传统的session类型的web应用应该使用这个方式来保存context。
NullSecurityContextRepository ：新建一个。适用于无状态的应用，比如使用JWT
RequestAttributeSecurityContextRepository ：从Requst的Attribute恢复出context

## AuthorizationServerContextFilter

OAuth2AuthorizationServerConfigurer

AuthorizationServerContext的持有者，它使用ThreadLocal将AuthorizationServerContext与当前线程关联。

AuthorizationServerContext 保存授权服务器运行时环境信息的上下文。

## HeaderWriterFilter

HeadersConfigurer

为了安全考虑，添加启用浏览器保护的某些头是很有用的，比如X-Frame-Options, X-XSS-Protection和X-Content-Type-Options

而HeaderWriterFilter就支持往响应头写入各种响应头

https://blog.csdn.net/qq_41662584/article/details/132918806

https://www.cnblogs.com/shigongp/p/17344009.html

## CsrfFilter

CsrfConfigurer

Csrf(跨站伪造请求)：指的是用户在A网站认证完成后，A网站Cookie保存在了浏览器中，然后用户在B网站点击了钓鱼链接，使其让钓鱼请求带有了A网站的Cookie，从而让A网站认为这是一次正常的请求
而SpringSecurity采用的是同步令牌模式(Synchronizer Token Pattern)来预防Csrf攻击
STP本意是每一次请求都会生成一个随机的令牌，然后下次发起请求时带上此令牌，如此循环往复，但是每次都生成令牌对于服务器的性能有要求
所以说SpringSecurity放宽了要求，在认证之前会生成一次令牌，以及每次认证后重新生成令牌

##   OidcLogoutEndpointFilter

OidcLogoutEndpointConfigurer

spring authorization server OIDC协议，支持处理依赖方（客户端）发起的登出请求，注销授权服务器端的会话

流程：
客户端登出成功->跳转到授权服务端OIDC登出端点->授权服务端注销会话->跳转回客户端(可选)

##   LogoutFilter

LogoutConfigurer

https://blog.csdn.net/zhouwenjun0820/article/details/129692319

https://juejin.cn/post/7270395503821209658

SpringSecurity默认提供了登录的页面以及登录的接口，与之对应的也提供了登出页和登出请求

登出请求对应的过滤器是LogoutFilter

##   OAuth2AuthorizationServerMetadataEndpointFilter

OAuth2AuthorizationServerMetadataEndpointConfigurer

该规范的目的是提供一个开放端点方便**OAuth2**客户端获取授权服务器的一些配置信息、支持信息，以达到自动配置**Provider**的目的。该规范要求提供一个路径为`/.well-known/*`的**URI**，后缀推荐`oauth-authorization-server`，并支持**GET**请求。

授权服务器收到该请求后，会把授权服务器元数据对象`OAuth2AuthorizationServerMetadata`以JSON的形式返回给**OAuth2**客户端

##   OAuth2AuthorizationEndpointFilter

OAuth2AuthorizationEndpointConfigurer

在处理/oauth2/authorize接口的过滤器`OAuth2AuthorizationEndpointFilter`中看一下实现逻辑，看一下对于认证信息的处理。先由converter处理，之后再由provider处理，之后判断认证信息是否已经认证过了，没认证过不处理，交给后边的过滤器处理，接下来看一下converter中的逻辑

https://juejin.cn/post/7254096495184134181

##   OAuth2DeviceVerificationEndpointFilter

##   OidcProviderConfigurationEndpointFilter

##   NimbusJwkSetEndpointFilter

##   OAuth2ClientAuthenticationFilter

##   BearerTokenAuthenticationFilter

##   RequestCacheAwareFilter

##   SecurityContextHolderAwareRequestFilter

##   AnonymousAuthenticationFilter

##   ExceptionTranslationFilter

##   AuthorizationFilter

##   OAuth2TokenEndpointFilter

##   OAuth2TokenIntrospectionEndpointFilter

##   OAuth2TokenRevocationEndpointFilter

##   OAuth2DeviceAuthorizationEndpointFilter

##   OidcUserInfoEndpointFilter



## ObjectPostProcessor

用于将创建的对象交给spring容器管理
https://www.cnblogs.com/LBJboy/articles/17663600.html

# springboot security启动

在springboot启动的时候，首先会进行初始化 AuthenticationConfiguration中Bean。三个配置类
	

```java
@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}
	
@Bean
public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(
		ApplicationContext context) {
	return new InitializeUserDetailsBeanManagerConfigurer(context);
}

@Bean
public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(
		ApplicationContext context) {
	return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
}
```
    @Bean
    public UserDetailsService users(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("admin")
                .password(passwordEncoder.encode("123456"))
                .roles("admin", "normal", "unAuthentication")
                .authorities("app", "web", "/test2", "/test3")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

首先通过HttpSecurityConfiguration.httpSecurity()中的HttpSecurityConfiguration.thenticationManager()方法，

然后通过AuthenticationConfiguration.getAuthenticationManager()执行this.authenticationManager = authBuilder.build();然后执行InitializeUserDetailsManagerConfigurer.configure(AuthenticationManagerBuilder auth)。将UserDetailsService和PasswordEncoder注入到DaoAuthenticationProvider。

UserDetailsService 初始化会在InitializeUserDetailsBeanManagerConfigurer中的内部类InitializeUserDetailsManagerConfigurer的configure(AuthenticationManagerBuilder auth)进行

PasswordEncoder同样会在InitializeUserDetailsBeanManagerConfigurer中的内部类InitializeUserDetailsManagerConfigurer的configure(AuthenticationManagerBuilder auth)进行

AuthenticationConfiguration类里面的Bean初始化

AbstractConfiguredSecurityBuilder.configure() --> InitializeUserDetailsManagerConfigurer.configure(AuthenticationManagerBuilder auth) --> DaoAuthenticationProvider.setUserDetailsService(UserDetailsService userDetailsService)

# 过滤器链

## 进行登录授权

http://127.0.0.1:8080/oauth2/authorize?client_id=messaging-client&response_type=code&scope=message.read&redirect_uri=https://www.baidu.com

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  AuthorizationServerContextFilter
  HeaderWriterFilter
  CsrfFilter
  OidcLogoutEndpointFilter
  LogoutFilter
  OAuth2AuthorizationServerMetadataEndpointFilter
  OAuth2AuthorizationEndpointFilter
  OAuth2DeviceVerificationEndpointFilter
  OidcProviderConfigurationEndpointFilter
  NimbusJwkSetEndpointFilter
  OAuth2ClientAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
  OAuth2TokenEndpointFilter
  OAuth2TokenIntrospectionEndpointFilter
  OAuth2TokenRevocationEndpointFilter
  OAuth2DeviceAuthorizationEndpointFilter
  OidcUserInfoEndpointFilter
]
```

## 重定向到登录页面

GET http://127.0.0.1:8080/login

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```

## 输入账号和密码登录

POST http://127.0.0.1:8080/login

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```

## 跳进行重定向

GET /oauth2/authorize?client_id=messaging-client&response_type=code&scope=message.read&redirect_uri=https://www.baidu.com&continue

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  AuthorizationServerContextFilter
  HeaderWriterFilter
  CsrfFilter
  OidcLogoutEndpointFilter
  LogoutFilter
  OAuth2AuthorizationServerMetadataEndpointFilter
  OAuth2AuthorizationEndpointFilter
  OAuth2DeviceVerificationEndpointFilter
  OidcProviderConfigurationEndpointFilter
  NimbusJwkSetEndpointFilter
  OAuth2ClientAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
  OAuth2TokenEndpointFilter
  OAuth2TokenIntrospectionEndpointFilter
  OAuth2TokenRevocationEndpointFilter
  OAuth2DeviceAuthorizationEndpointFilter
  OidcUserInfoEndpointFilter
]
```

## 跳转到授权页面

GET http://127.0.0.1:8080/oauth2/consent?scope=message.read&client_id=messaging-client&state=tQ3f7OeautXRM9OUgNY8dhB0wCcvlDHcx4Jr49kyb6A%3D

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```



## 点击授权换取code

POST http://127.0.0.1:8080/oauth2/authorize

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  AuthorizationServerContextFilter
  HeaderWriterFilter
  CsrfFilter
  OidcLogoutEndpointFilter
  LogoutFilter
  OAuth2AuthorizationServerMetadataEndpointFilter
  OAuth2AuthorizationEndpointFilter
  OAuth2DeviceVerificationEndpointFilter
  OidcProviderConfigurationEndpointFilter
  NimbusJwkSetEndpointFilter
  OAuth2ClientAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
  OAuth2TokenEndpointFilter
  OAuth2TokenIntrospectionEndpointFilter
  OAuth2TokenRevocationEndpointFilter
  OAuth2DeviceAuthorizationEndpointFilter
  OidcUserInfoEndpointFilter
]
```



## 携带code等信息获取accesstoken

POST http://127.0.0.1:8080/oauth2/token

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  AuthorizationServerContextFilter
  HeaderWriterFilter
  CsrfFilter
  OidcLogoutEndpointFilter
  LogoutFilter
  OAuth2AuthorizationServerMetadataEndpointFilter
  OAuth2AuthorizationEndpointFilter
  OAuth2DeviceVerificationEndpointFilter
  OidcProviderConfigurationEndpointFilter
  NimbusJwkSetEndpointFilter
  OAuth2ClientAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
  OAuth2TokenEndpointFilter
  OAuth2TokenIntrospectionEndpointFilter
  OAuth2TokenRevocationEndpointFilter
  OAuth2DeviceAuthorizationEndpointFilter
  OidcUserInfoEndpointFilter
]
```



## 携带accesstoken进行测试

GET http://127.0.0.1:8080/test01

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```





## 过滤器链

```java
SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
使用的过滤器链
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  AuthorizationServerContextFilter
  HeaderWriterFilter
  CsrfFilter
  OidcLogoutEndpointFilter
  LogoutFilter
  OAuth2AuthorizationServerMetadataEndpointFilter
  OAuth2AuthorizationEndpointFilter
  OAuth2DeviceVerificationEndpointFilter
  OidcProviderConfigurationEndpointFilter
  NimbusJwkSetEndpointFilter
  OAuth2ClientAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
  OAuth2TokenEndpointFilter
  OAuth2TokenIntrospectionEndpointFilter
  OAuth2TokenRevocationEndpointFilter
  OAuth2DeviceAuthorizationEndpointFilter
  OidcUserInfoEndpointFilter
]
```



## 过滤器链2

```java
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)

Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```

UsernamePasswordAuthenticationFilter初始化流程

在http进行build的时候，会对FormLoginConfigurer进行初始化，最终调用AbstractAuthenticationFilterConfigurer.configure(B http)的方法进行UsernamePasswordAuthenticationFilter设置

http://127.0.0.1:8080/oauth2/authorize?client_id=messaging-client&response_type=code&scope=message.read&redirect_uri=https://www.baidu.com
访问的时候，会跳转到登录页面，然后进行账号和密码的输入，进入到UsernamePasswordAuthenticationFilter.attemptAuthentication(HttpServletRequest request, HttpServletResponse response)进行账号和密码的验证。认证成功之后调用SavedRequestAwareAuthenticationSuccessHandler.onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,Authentication authentication)进行认证跳转
http://127.0.0.1:8080/oauth2/consent?scope=message.read&client_id=messaging-client&state=wQEttQyBNGapZje-96D1dzi-sNyBhaCRVbTxXpkBSuk%3D

https://www.baidu.com/?code=ybYVo87hpcl9yyDReYjq_z7aIF8n2PZQUxpRMrW_ArqjgKILBFf1JnaMeB-PIylx62MJosJ5CM4TzhuaCvtzMVyAizw7pMXu1GAxX2EdfEKYTfpeOZpXN4Z82AqMu23o

## code换取token

经过OAuth2ClientAuthenticationFilter过滤器，通过DelegatingAuthenticationConverter.convert(HttpServletRequest request)进行转换，获取basicAuth中的clientID和clientSecret。并创建OAuth2ClientAuthenticationToken。并通过ProviderManager.authenticate(Authentication authentication)进行认证。委托给JwtClientAssertionAuthenticationProvider.authenticate(Authentication authentication)进行认证,认证不成功，用ClientSecretAuthenticationProvider.authenticate(Authentication authentication)进行认证,对账号和密码进行验证，对code进行验证。

AuthorizationFilter进行用户url验证

## 调用接口进行

```java
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  BearerTokenAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```


BearerTokenAuthenticationFilter 通过ProviderManager.authenticate(Authentication authentication),然后通过JwtAuthenticationProvider.authenticate(Authentication authentication)生成token.最终调用AuthorizationFilter过滤器，然后通过RequestMatcherDelegatingAuthorizationManager.check(Supplier<Authentication> authentication, HttpServletRequest request)中RequestMatcher.matcher(HttpServletRequest request)中AuthenticatedAuthorizationManager.check(Supplier<Authentication> authentication, T object)进行处理