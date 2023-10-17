package com.app.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.security.model.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long>{

	public AppUser findUserByUsername(String username);
}
