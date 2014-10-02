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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Auto-configure a Spring Security OAuth2 resource server. Back off if another component already exists or
 * if resource server is disabled (in the event of using an external one).
 *
 * @author Greg Turnquist
 */
@Configuration
@ConditionalOnClass(EnableResourceServer.class)
@ConditionalOnMissingBean(annotation = EnableResourceServer.class)
public class SpringSecurityOAuth2ResourceServerAutoConfiguration {

	@Configuration
	@EnableResourceServer
	public static class ResourceServer extends ResourceServerConfigurerAdapter {

		@Autowired
		private SpringSecurityOAuth2Properties config;

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			resources.resourceId(config.getResourceId());
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
				.and()
					.httpBasic()
				.and()
					.csrf()
						.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/**")).disable();
		}

	}
}
