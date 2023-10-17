package com.app.security.controller;

import java.security.Principal;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.security.config.SecurityConfig;
import com.app.security.dto.UserRoleDto;
import com.app.security.filter.JwtUtils;
import com.app.security.model.AppRole;
import com.app.security.model.AppUser;
import com.app.security.service.SecurityService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/api/v1")
public class AppUserAppRoleController {

	@Autowired
	private SecurityService securityService;
	
	@GetMapping("/users")
	@PreAuthorize("hasAuthority('USER')")
	public List<AppUser> getUsers(){
		return securityService.getUsers();
	}
	
	@PostMapping("/users")
	@PreAuthorize("hasAuthority('ADMIN')")
	public AppUser addUser(@RequestBody AppUser user) {
		return securityService.addUser(user);
	}
	
	@PostMapping("/roles")
	@PreAuthorize("hasAuthority('ADMIN')")
	public AppRole addRole(@RequestBody AppRole role) {
		return securityService.addRole(role);
	}
	
	@PutMapping("/users/roles")
	@PreAuthorize("hasAuthority('ADMIN')")
	public AppUser addRoleToUser(@RequestBody UserRoleDto userRoleDto) {
		AppUser user = securityService.getUserById(userRoleDto.getUserId());
		AppRole role = securityService.getRoleById(userRoleDto.getRoleId());
		return securityService.addRoleToUser(user, role);
	}
	
	@DeleteMapping("/users/roles")
	@PreAuthorize("hasAuthority('ADMIN')")
	public AppUser removeRoleFromUser(@RequestBody UserRoleDto userRoleDto) {
		AppUser user = securityService.getUserById(userRoleDto.getUserId());
		AppRole role = securityService.getRoleById(userRoleDto.getRoleId());
		return securityService.removeRoleFromUser(user, role);
	}
	
	@GetMapping("/refreshToken")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
		System.out.println("hello");
		String authorization = request.getHeader("Authorization");
		if(authorization != null && authorization.startsWith("Bearer ")) {
			try {
				String referehToken = authorization.substring(7);
				Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
				JWTVerifier jwtVerifier = JWT.require(algorithm).build();
				DecodedJWT decodedRefreshToken = jwtVerifier.verify(referehToken);
				String username = decodedRefreshToken.getSubject();
				AppUser user = securityService.getUserByUsername(username);
				String accessToken = JWT.create()
						.withSubject(username)
						.withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.ACCESS_TOKEN_EXPIRES *60*1000))
						.withIssuer(request.getRequestURL().toString())
						.withClaim("roles", user.getRoles().stream().map(x -> x.getName()).collect(Collectors.toList()) )
						.sign(algorithm);
				Map<String, String> tokens = new HashMap<>();
				tokens.put("accessToken", accessToken);
				tokens.put("refreshTokeen", referehToken);
				response.setContentType("application/json");
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
			}catch(Exception exception) {
				response.setHeader("error-message", exception.getMessage());
				response.sendError(403);
			}
		}
		else {
			throw new RuntimeException("refresh token required");
		}
	}
	
	@GetMapping("/profile")
	public AppUser profile(Authentication authentication) {
		return securityService.getUserByUsername(authentication.getName());
	}
}
