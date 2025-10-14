package com.TreasureHunter.GatewayService;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class GatewayApplication {

	@Bean
	public ApplicationRunner testRoutes(RouteLocator locator) {
		return args -> locator.getRoutes().subscribe(route ->
				System.out.println("✅ Loaded route: " + route.getId() + " -> " + route.getUri()));
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

}
