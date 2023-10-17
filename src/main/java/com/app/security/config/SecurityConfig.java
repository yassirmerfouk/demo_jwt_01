package com.app.security.config;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.app.security.filter.JwtAuthenticationFilter;
import com.app.security.filter.JwtAuthorizationFilter;
import com.app.security.model.AppUser;
import com.app.security.service.SecurityService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired 
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Pass userDetailservice Implementation to the spring filter to use it to get the user from database 
		auth.userDetailsService(userDetailsService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Disable csrf from spring security , we don't need it
		http.csrf().disable();
		// Tell to spring to use an stateless authentication, not statefull (default)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// Make the refreshtoken end point can be acces without authenticated
		http.authorizeRequests().antMatchers("/api/v1/refreshToken").permitAll();
		// Make all other end point needs authentication
		http.authorizeRequests().anyRequest().authenticated();
		// Tell spring to use JwtAuthenticationFilter for authentication /login
		http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
		// Tell spring to use JwtAuthorisationFilter before any other filter or path called
		http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	// Create an AuthenticationManagerBean to use it in JwtAuthenticationFilter class
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManagerBean();
	}
}
