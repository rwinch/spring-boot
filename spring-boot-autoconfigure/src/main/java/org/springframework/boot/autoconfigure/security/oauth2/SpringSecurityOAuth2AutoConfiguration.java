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

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * Spring Security OAuth2 top level auto-configuration beans
 *
 * @author Greg Turnquist
 */
@Configuration
@ConditionalOnClass({ OAuth2AccessToken.class })
@ConditionalOnWebApplication
@Import({SpringSecurityOAuth2AuthorizationServerAutoConfiguration.class,
		SpringSecurityOAuth2MethodSecurityAutoConfiguration.class,
		SpringSecurityOAuth2ResourceServerAutoConfiguration.class})
@AutoConfigureBefore(WebMvcAutoConfiguration.class)
@EnableWebMvcSecurity
public class SpringSecurityOAuth2AutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public SpringSecurityOAuth2Properties springSecurityOauth2Properties() {
		return new SpringSecurityOAuth2Properties();
	}

	@Bean
	@ConditionalOnMissingBean
	public UserApprovalHandler userApprovalHandler() {
		return new DefaultUserApprovalHandler();
	}

	@Bean
	@ConditionalOnMissingBean
	public TokenStore tokenStore() {
		return new InMemoryTokenStore();
	}

	@Bean
	@ConditionalOnMissingBean
	public DefaultTokenServices tokenService(TokenStore tokenStore) {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setTokenStore(tokenStore);
		return tokenServices;
	}

}
