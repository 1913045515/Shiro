package com.shiro.test1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
//@PropertySource("classpath:spring-shiro-web.xml")
public class SpringBootShiroTest1Application {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootShiroTest1Application.class, args);
	}
}
