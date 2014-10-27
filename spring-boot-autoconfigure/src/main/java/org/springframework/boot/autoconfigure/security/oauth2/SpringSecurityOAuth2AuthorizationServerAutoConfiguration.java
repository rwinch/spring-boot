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

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

/**
 * Auto-configure a Spring Security OAuth2 authorization server. Back off if another component already exists or
 * if authorization server is disabled (in the event of using an external one).
 *
 * @author Greg Turnquist
 */
@Configuration
@ConditionalOnClass(EnableAuthorizationServer.class)
@ConditionalOnMissingBean(annotation = EnableAuthorizationServer.class)
public class SpringSecurityOAuth2AuthorizationServerAutoConfiguration {

	@Configuration
	@EnableAuthorizationServer
	public static class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private SpringSecurityOAuth2Properties config;

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private UserApprovalHandler userApprovalHandler;

		@Autowired
		private TokenStore tokenStore;

		@Bean
		@ConditionalOnMissingBean
		public ApprovalStore approvalStore(final TokenStore tokenStore) {
			TokenApprovalStore approvalStore = new TokenApprovalStore();
			approvalStore.setTokenStore(tokenStore);
			return approvalStore;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients
					.inMemory()
					.withClient(config.getClientId())
					.secret(config.getSecret())
					.resourceIds(config.getResourceId())
					.authorizedGrantTypes(config.getAuthorizationTypes())
					.authorities(config.getAuthorities())
					.scopes(config.getScopes())
					.redirectUris(config.getRedirectUris());
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
					.tokenStore(tokenStore)
					.authenticationManager(authenticationManager)
					.userApprovalHandler(userApprovalHandler);
		}

		@PostConstruct
		public void init() {
			ConfigurationProperties ann = AnnotationUtils.findAnnotation(
					SpringSecurityOAuth2Properties.class, ConfigurationProperties.class);
			String prefix = ann.prefix();
			System.out.println();
			System.out.println(prefix + ".clientId=" + config.getClientId());
			System.out.println(prefix + ".secret=" + config.getSecret());
			System.out.println(prefix + ".resourceId=" + config.getResourceId());
			System.out.println(prefix + ".authorizationTypes=" +
					StringUtils.arrayToCommaDelimitedString(config.getAuthorizationTypes()));
			System.out.println(prefix + ".scopes=" +
					StringUtils.arrayToCommaDelimitedString(config.getScopes()));
			System.out.println(prefix + ".redirectUris=" +
					StringUtils.arrayToCommaDelimitedString(config.getRedirectUris()));
			System.out.println();
		}
	}
}
