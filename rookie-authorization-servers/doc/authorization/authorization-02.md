

## springboot security启动

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
然后通过HttpSecurityConfiguration类将AuthenticationConfiguration注入进去，最终通过HttpSecurityConfiguration.httpSecurity()往下面进行

UserDetailsService 初始化会在InitializeUserDetailsBeanManagerConfigurer中的内部类InitializeUserDetailsManagerConfigurer的configure(AuthenticationManagerBuilder auth)进行

PasswordEncoder同样会在InitializeUserDetailsBeanManagerConfigurer中的内部类InitializeUserDetailsManagerConfigurer的configure(AuthenticationManagerBuilder auth)进行


上面会在HttpSecurityConfiguration.httpSecurity()中HttpSecurityConfiguration.authenticationManager()中AuthenticationConfiguration.getAuthenticationManager()中在AbstractConfiguredSecurityBuilder.doBuild()方法中调用AbstractConfiguredSecurityBuilder.configure()中进行

## 过滤器链1

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