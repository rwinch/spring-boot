/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package smoketest.rsocket;

import io.rsocket.ConnectionSetupPayload;
import io.rsocket.RSocket;
import io.rsocket.SocketAcceptor;
import io.rsocket.plugins.SocketAcceptorInterceptor;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import org.springframework.boot.rsocket.server.RSocketServerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
public class SubscribeOnConfiguration {

	@Bean
	@Profile("default")
	RSocketServerCustomizer subscribeOnBoundidElasticSocketAcceptor() {
		SocketAcceptorInterceptor mockAcceptor = (a) -> new SubscribeOnSocketAcceptor(a, Schedulers.boundedElastic());
		return (server) -> server.interceptors((registry) -> registry.forSocketAcceptor(mockAcceptor));
	}

	@Bean
	@Profile("immediate")
	RSocketServerCustomizer subscribeOnImmediateSocketAcceptor() {
		SocketAcceptorInterceptor mockAcceptor = (a) -> new SubscribeOnSocketAcceptor(a, Schedulers.immediate());
		return (server) -> server.interceptors((registry) -> registry.forSocketAcceptor(mockAcceptor));
	}

	static class SubscribeOnSocketAcceptor implements SocketAcceptor {

		private final SocketAcceptor delegate;

		private final Scheduler scheduler;

		SubscribeOnSocketAcceptor(SocketAcceptor delegate, Scheduler scheduler) {
			this.delegate = delegate;
			this.scheduler = scheduler;
		}

		@Override
		public Mono<RSocket> accept(ConnectionSetupPayload connectionSetupPayload, RSocket rSocket) {
			return this.delegate.accept(connectionSetupPayload, rSocket).subscribeOn(this.scheduler);
		}

	}

}
