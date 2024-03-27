# OAuth2AuthorizationEndpointFilter

通过查看API 知道，获取授权码的Filter为 OAuth2AuthorizationEndpointFilter

```java
public final class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
	/**
	 * 默认请求端点
	 */
	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher authorizationEndpointMatcher;
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
	private SessionAuthenticationStrategy sessionAuthenticationStrategy = (authentication, request, response) -> {};
	private String consentPage;

	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, String authorizationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
        //端点匹配规则
		this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
        //委托类，里面有两个类来实现
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new OAuth2AuthorizationCodeRequestAuthenticationConverter(),
						new OAuth2AuthorizationConsentAuthenticationConverter()));
	}

	private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        //默认匹配/oauth2/authorize,GET方法
		RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.GET.name());
           //默认匹配/oauth2/authorize,POST方法
		RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.POST.name());
        //SCOPE包含openid的请求
		RequestMatcher openidScopeMatcher = request -> {
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
		};
        //包含response_type的请求
		RequestMatcher responseTypeParameterMatcher = request ->
				request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

		RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
				authorizationRequestGetMatcher,
				new AndRequestMatcher(
						authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
		RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
				authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

		return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.authorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authentication)
						.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
            //第一次请求时匿名用户
			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

			if (!authenticationResult.isAuthenticated()) {
				// If the Principal (Resource Owner) is not authenticated then
				// pass through the chain with the expectation that the authentication process
				// will commence via AuthenticationEntryPoint
				filterChain.doFilter(request, response);
				return;
			}

			if (authenticationResult instanceof OAuth2AuthorizationConsentAuthenticationToken) {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Authorization consent is required");
				}
				sendAuthorizationConsent(request, response,
						(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication,
						(OAuth2AuthorizationConsentAuthenticationToken) authenticationResult);
				return;
			}

			this.sessionAuthenticationStrategy.onAuthentication(
					authenticationResult, request, response);

			this.authenticationSuccessHandler.onAuthenticationSuccess(
					request, response, authenticationResult);

		} catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Authorization request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
	 *
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
	 * @since 0.3.1
	 */
	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or {@link OAuth2AuthorizationConsentAuthenticationToken}
	 * used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Sets the {@link SessionAuthenticationStrategy} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * before calling the {@link AuthenticationSuccessHandler}.
	 * If OpenID Connect is enabled, the default implementation tracks OpenID Connect sessions using a {@link SessionRegistry}.
	 *
	 * @param sessionAuthenticationStrategy the {@link SessionAuthenticationStrategy} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @since 1.1
	 */
	public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		Assert.notNull(sessionAuthenticationStrategy, "sessionAuthenticationStrategy cannot be null");
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
	}

	/**
	 * Specify the URI to redirect Resource Owners to if consent is required. A default consent
	 * page will be generated when this attribute is not specified.
	 *
	 * @param consentPage the URI of the custom consent page to redirect to if consent is required (e.g. "/oauth2/consent")
	 */
	public void setConsentPage(String consentPage) {
		this.consentPage = consentPage;
	}

	private void sendAuthorizationConsent(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication) throws IOException {

		String clientId = authorizationConsentAuthentication.getClientId();
		Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
		Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
		Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
		String state = authorizationConsentAuthentication.getState();

		if (hasConsentUri()) {
			String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
					.queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
					.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
					.queryParam(OAuth2ParameterNames.STATE, state)
					.toUriString();
			this.redirectStrategy.sendRedirect(request, response, redirectUri);
		} else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Displaying generated consent screen");
			}
			DefaultConsentPage.displayConsent(request, response, clientId, principal, requestedScopes, authorizedScopes, state, Collections.emptyMap());
		}
	}

	private boolean hasConsentUri() {
		return StringUtils.hasText(this.consentPage);
	}

	private String resolveConsentUri(HttpServletRequest request) {
		if (UrlUtils.isAbsoluteUrl(this.consentPage)) {
			return this.consentPage;
		}
		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
		urlBuilder.setScheme(request.getScheme());
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(request.getServerPort());
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo(this.consentPage);
		return urlBuilder.getUrl();
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.CODE, authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(
					OAuth2ParameterNames.STATE,
					UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
		}
		String redirectUri = uriBuilder.build(true).toUriString();		// build(true) -> Components are explicitly encoded
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
				(OAuth2AuthorizationCodeRequestAuthenticationException) exception;
		OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

		if (authorizationCodeRequestAuthentication == null ||
				!StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
			return;
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Redirecting to client with error");
		}

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(
					OAuth2ParameterNames.ERROR_DESCRIPTION,
					UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(
					OAuth2ParameterNames.ERROR_URI,
					UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
		}
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(
					OAuth2ParameterNames.STATE,
					UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
		}
		String redirectUri = uriBuilder.build(true).toUriString();		// build(true) -> Components are explicitly encoded
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

}

```

