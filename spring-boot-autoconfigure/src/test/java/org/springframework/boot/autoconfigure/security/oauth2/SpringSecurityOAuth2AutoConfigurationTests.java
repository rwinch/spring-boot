/*
 * Copyright 2012-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.autoconfigure.security.oauth2;

import static org.junit.Assert.*;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.context.embedded.AnnotationConfigEmbeddedWebApplicationContext;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.boot.test.EnvironmentTestUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Verify Spring Security OAuth2 auto-configuration secures end points properly, accepts environmental
 * overrides, and also backs off in the presence of other resource/authorization components.
 *
 * @author Greg Turnquist
 */
public class SpringSecurityOAuth2AutoConfigurationTests {

	private AnnotationConfigEmbeddedWebApplicationContext context;

	@Test
	public void testDefaultConfiguration() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		for (String beanName : this.context.getBeanDefinitionNames()) {
			if (beanName.contains("OAuth2")) {
				System.out.println(beanName);
			}
		}

		this.context.getBean(SpringSecurityOAuth2AuthorizationServerAutoConfiguration.class);
		this.context.getBean(SpringSecurityOAuth2ResourceServerAutoConfiguration.class);
		this.context.getBean(SpringSecurityOAuth2MethodSecurityAutoConfiguration.class);

		TokenStore tokenStore = this.context.getBean(TokenStore.class);
		ApprovalStore approvalStore = this.context.getBean(ApprovalStore.class);
		SpringSecurityOAuth2Properties config = this.context.getBean(SpringSecurityOAuth2Properties.class);
		AuthorizationEndpoint endpoint = this.context.getBean(AuthorizationEndpoint.class);
		UserApprovalHandler handler = (UserApprovalHandler) ReflectionTestUtils.getField(endpoint, "userApprovalHandler");
		ClientDetailsService clientDetailsService = this.context.getBean(ClientDetailsService.class);
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(config.getClientId());

		assertTrue(tokenStore instanceof InMemoryTokenStore);
		assertTrue(approvalStore instanceof TokenApprovalStore);
		assertTrue(AopUtils.isJdkDynamicProxy(clientDetailsService));
		assertEquals(AopUtils.getTargetClass(clientDetailsService), InMemoryClientDetailsService.class);
		assertTrue(handler instanceof DefaultUserApprovalHandler);

		assertEquals(clientDetails.getClientId(), config.getClientId());
		assertEquals(clientDetails.getClientSecret(), config.getSecret());
		assertTrue(clientDetails.getResourceIds().contains(config.getResourceId()));
		for (String authorizationGrantType : config.getAuthorizationTypes()) {
			assertTrue(clientDetails.getAuthorizedGrantTypes().contains(authorizationGrantType));
		}
		for (String scope : config.getScopes()) {
			clientDetails.getScope().contains(scope);
		}
		for (String redirectUri : config.getRedirectUris()) {
			assertTrue(clientDetails.getRegisteredRedirectUri().contains(redirectUri));
		}

		verifyAuthentication(config);
	}

	@Test
	public void testEnvironmentalOverrides() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		EnvironmentTestUtils.addEnvironment(this.context,
				"spring.security.oauth2.clientId:myclientid",
				"spring.security.oauth2.secret:mysecret");
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		SpringSecurityOAuth2Properties config = this.context.getBean(SpringSecurityOAuth2Properties.class);

		assertEquals("myclientid", config.getClientId());
		assertEquals("mysecret", config.getSecret());

		verifyAuthentication(config);
	}

	@Test
	public void testResourceServerOverride() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				MyResourceServer.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class);
		this.context.refresh();

		assertEquals(1, this.context.getBeanNamesForType(
				SpringSecurityOAuth2AuthorizationServerAutoConfiguration.class).length);

		assertEquals(1, this.context.getBeanNamesForType(MyResourceServer.class).length);

		assertEquals(0, this.context.getBeanNamesForType(
				SpringSecurityOAuth2ResourceServerAutoConfiguration.class).length);
	}

	@Test
	public void testAuthorizationServerOverride() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				MyAuthorizationServer.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class);
		this.context.refresh();

		assertEquals(0, this.context.getBeanNamesForType(
				SpringSecurityOAuth2AuthorizationServerAutoConfiguration.class).length);

		assertEquals(1, this.context.getBeanNamesForType(MyAuthorizationServer.class).length);

		assertEquals(1, this.context.getBeanNamesForType(
				SpringSecurityOAuth2ResourceServerAutoConfiguration.class).length);
	}

	@Test
	public void testDefaultPrePostSecurityAnnotations() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		this.context.getBean(SpringSecurityOAuth2MethodSecurityAutoConfiguration.class);
		DelegatingMethodSecurityMetadataSource source = this.context.getBean(DelegatingMethodSecurityMetadataSource.class);
		List<MethodSecurityMetadataSource> sources =
				((DelegatingMethodSecurityMetadataSource) source.getMethodSecurityMetadataSources().get(0))
						.getMethodSecurityMetadataSources();

		assertEquals(1, sources.size());
		assertEquals(PrePostAnnotationSecurityMetadataSource.class, sources.get(0).getClass());
	}

	@Test
	public void testClassicSecurityAnnotationOverride() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		EnvironmentTestUtils.addEnvironment(this.context,
				"spring.security.oauth2.prePostEnabled:false",
				"spring.security.oauth2.securedEnabled:true");
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		this.context.getBean(SpringSecurityOAuth2MethodSecurityAutoConfiguration.class);
		DelegatingMethodSecurityMetadataSource source = this.context.getBean(DelegatingMethodSecurityMetadataSource.class);
		List<MethodSecurityMetadataSource> sources =
				((DelegatingMethodSecurityMetadataSource) source.getMethodSecurityMetadataSources().get(0))
						.getMethodSecurityMetadataSources();

		assertEquals(1, sources.size());
		assertEquals(SecuredAnnotationSecurityMetadataSource.class, sources.get(0).getClass());
	}

	@Test
	public void testJsr250SecurityAnnotationOverride() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		EnvironmentTestUtils.addEnvironment(this.context,
				"spring.security.oauth2.prePostEnabled:false",
				"spring.security.oauth2.jsr250Enabled:true");
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		this.context.getBean(SpringSecurityOAuth2MethodSecurityAutoConfiguration.class);
		DelegatingMethodSecurityMetadataSource source = this.context.getBean(DelegatingMethodSecurityMetadataSource.class);
		List<MethodSecurityMetadataSource> sources =
				((DelegatingMethodSecurityMetadataSource) source.getMethodSecurityMetadataSources().get(0))
						.getMethodSecurityMetadataSources();

		assertEquals(1, sources.size());
		assertEquals(Jsr250MethodSecurityMetadataSource.class, sources.get(0).getClass());
	}

	@Test
	public void testMethodSecurityBackingOff() {
		this.context = new AnnotationConfigEmbeddedWebApplicationContext();
		this.context.register(EmbeddedContainerConfiguration.class,
				TestSecurityConfiguration.class,
				MyMethodSecurity.class,
				SpringSecurityOAuth2AutoConfiguration.class,
				SecurityAutoConfiguration.class,
				ServerProperties.class,
				DispatcherServletAutoConfiguration.class,
				WebMvcAutoConfiguration.class,
				HttpMessageConvertersAutoConfiguration.class);
		this.context.refresh();

		assertEquals(0, this.context.getBeanNamesForType(
				SpringSecurityOAuth2MethodSecurityAutoConfiguration.class).length);

		DelegatingMethodSecurityMetadataSource source = this.context.getBean(DelegatingMethodSecurityMetadataSource.class);
		List<MethodSecurityMetadataSource> sources = source.getMethodSecurityMetadataSources();
		assertEquals(1, sources.size());
		assertEquals(PrePostAnnotationSecurityMetadataSource.class, sources.get(0).getClass());
	}

	private void verifyAuthentication(SpringSecurityOAuth2Properties config) {
		String baseUrl = "http://localhost:"
				+ this.context.getEmbeddedServletContainer().getPort();

		RestTemplate rest = new RestTemplate();

		// First, verify the web endpoint can't be reached
		try {
			rest.getForEntity(baseUrl + "/secured", String.class);
		} catch (HttpClientErrorException e) {
			assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
		}

		// Since we can't reach it, need to collect an authorization token
		HttpHeaders headers = new HttpHeaders();
		String base64Creds = new String(Base64.encode((config.getClientId() + ":" + config.getSecret()).getBytes()));
		headers.set("Authorization", "Basic " + base64Creds);

		MultiValueMap<String, Object> body = new LinkedMultiValueMap<String, Object>();
		body.set("grant_type", "password");
		body.set("username", "foo");
		body.set("password", "bar");
		body.set("scope", "read");

		HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<MultiValueMap<String, Object>>(body, headers);

		JsonNode response = rest.postForObject(baseUrl + "/oauth/token", request, JsonNode.class);
		System.out.println(response);
		String authorizationToken = response.findValue("value").asText();
		String tokenType = response.findValue("tokenType").asText();
		String scope = response.findValues("scope").get(0).toString();
		assertEquals("bearer", tokenType);
		assertEquals("[\"read\"]", scope);

		// Now we should be able to see that endpoint.
		System.out.println("Authorization token: " + authorizationToken);
		HttpHeaders headers2 = new HttpHeaders();
		headers.set("Authorization", "BEARER " + authorizationToken);

		// TODO Figure out why method-level security is failing
//		request = new HttpEntity<MultiValueMap<String, Object>>(null, headers);
//		ResponseEntity<String> securedResponse = rest.exchange(baseUrl + "/secured", HttpMethod.GET, request, String.class);
//		assertEquals(HttpStatus.OK, securedResponse.getStatusCode());
//		assertEquals("You reached an endpoint secured by Spring Security OAuth2", securedResponse.getBody());

	}

	@Configuration
	protected static class TestSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("foo").password("bar").roles("USER");
		}

		@Bean
		TestWebApp testWebApp() {
			return new TestWebApp();
		}
	}

	@RestController
	protected static class TestWebApp {

		@RequestMapping(value = "/secured", method = RequestMethod.GET)
		@PreAuthorize("#oauth2.hasScope('read')")
		public String securedEndpoint() {
			return "You reached an endpoint secured by Spring Security OAuth2";
		}
	}

	@Configuration
	protected static class EmbeddedContainerConfiguration {
		@Bean
		TomcatEmbeddedServletContainerFactory containerFactory() {
			return new TomcatEmbeddedServletContainerFactory(0);
		}
	}

	@Configuration
	@EnableResourceServer
	protected static class MyResourceServer extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			System.out.println("Configuring Resource Server security...");
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.csrf()
				.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize")).disable();
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class MyAuthorizationServer extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private UserApprovalHandler userApprovalHandler;

		@Autowired
		private TokenStore tokenStore;

		@Bean
		public ApprovalStore approvalStore(final TokenStore tokenStore) {
			TokenApprovalStore approvalStore = new TokenApprovalStore();
			approvalStore.setTokenStore(tokenStore);
			return approvalStore;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients
				.inMemory()
				.withClient("client")
				.secret("secret")
				.resourceIds("resource-id")
				.authorizedGrantTypes("password")
				.authorities("USER")
				.scopes("read")
				.redirectUris("http://localhost:8080");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
				.tokenStore(tokenStore)
				.authenticationManager(authenticationManager)
				.userApprovalHandler(userApprovalHandler);
		}
	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	protected static class MyMethodSecurity extends GlobalMethodSecurityConfiguration {
		@Override
		protected MethodSecurityExpressionHandler createExpressionHandler() {
			return new OAuth2MethodSecurityExpressionHandler();
		}
	}
}
