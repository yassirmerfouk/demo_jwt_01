package com.app.security.service;

import java.util.List;

import com.app.security.model.AppRole;
import com.app.security.model.AppUser;

public interface SecurityService {

	public AppUser addUser(AppUser user);
	public AppRole addRole(AppRole role);
	public AppUser addRoleToUser(AppUser user, AppRole role);
	public AppUser removeRoleFromUser(AppUser user, AppRole role);
	public List<AppUser> getUsers();
	
	public AppUser getUserById(Long id);
	public AppRole getRoleById(Long id);
	
	public AppUser getUserByUsername(String username);
}
