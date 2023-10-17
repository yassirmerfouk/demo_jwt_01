package com.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.app.security.model.AppRole;
import com.app.security.repository.AppRoleRepository;
import com.app.security.repository.AppUserRepository;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class DemoJwt01Application  implements CommandLineRunner{

	@Autowired 
	private AppRoleRepository appRoleRepository;
	
	@Autowired
	private AppUserRepository appUserRepository;
	
	
	public static void main(String[] args) {
		SpringApplication.run(DemoJwt01Application.class, args);
	}
	
	@Override
	public void run(String... args) throws Exception {
//		appRoleRepository.save(new AppRole(null, "USER"));
//		appRoleRepository.save(new AppRole(null, "ADMIN"));
	}
	
	@Bean
	public BCryptPasswordEncoder bCrypt() {
		return new BCryptPasswordEncoder();
	}

}
