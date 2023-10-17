package com.app.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.security.model.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, Long>{

}
