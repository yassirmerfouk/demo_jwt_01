package com.app.security.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.app.security.model.AppUser;

@Service
public class UserDetailServiceImp implements UserDetailsService{

	@Autowired
	private SecurityService securityService;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Get App user from database using SecurityService method : 
		AppUser appUser = securityService.getUserByUsername(username);
		// Create a List of GrantedAuthority based on AppUser roles 
		List<GrantedAuthority> authorities = appUser.getRoles().stream().map(appRole -> new SimpleGrantedAuthority(appRole.getName()))
				.collect(Collectors.toList());
		// Create a Spring user Object and pass to it username, password, authorities
		User user = new User(appUser.getUsername(), appUser.getPassword(), authorities);
		// Return the object to spring security filter chain (Security config class)
		return user;
	}
}
