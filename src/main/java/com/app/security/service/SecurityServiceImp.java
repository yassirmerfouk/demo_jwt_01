package com.app.security.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.app.security.model.AppRole;
import com.app.security.model.AppUser;
import com.app.security.repository.AppRoleRepository;
import com.app.security.repository.AppUserRepository;

@Service
public class SecurityServiceImp implements SecurityService{

	@Autowired 
	private AppUserRepository userRepository;
	@Autowired 
	private AppRoleRepository roleRepository;
	@Autowired
	private BCryptPasswordEncoder bCrypt;
	
	@Override
	public AppUser addUser(AppUser user) {
		user.setPassword(bCrypt.encode(user.getPassword()));
		return userRepository.save(user);
	}

	@Override
	public AppRole addRole(AppRole role) {
		return roleRepository.save(role);
	}

	@Override
	public AppUser addRoleToUser(AppUser user, AppRole role) {
		user.getRoles().add(role);
		return userRepository.save(user);
	}

	@Override
	public AppUser removeRoleFromUser(AppUser user, AppRole role) {
		user.getRoles().remove(role);
		return userRepository.save(user);
	}

	@Override
	public List<AppUser> getUsers() {
		return userRepository.findAll();
	}
	
	@Override
	public AppUser getUserById(Long id) {
		return userRepository.findById(id).get();
	}

	@Override
	public AppRole getRoleById(Long id) {
		return roleRepository.findById(id).get();
	}
	
	@Override
	public AppUser getUserByUsername(String username) {
		return userRepository.findUserByUsername(username);
	}
}
