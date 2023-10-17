package com.app.security.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

// create the JwtAuthenticationClass, is called when there is an /login call in post method
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private AuthenticationManager authenticationManager;
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		super();
		this.authenticationManager = authenticationManager;
	}

	// attemptAuthentication is called when the user send username and password to /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		// Get username and password data
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		// Create An authenticationToken object that conatains username and password
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
		// Pass the object to this method, it will send the object to SpringSecurity filter to extecute the UserDetailService
		return authenticationManager.authenticate(authenticationToken);
	}
	
	// If the user data are correct this method will be executed to generate the access token and refreshToken and send it to the client
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		// Get the spring user object authenticated
		User user = (User) authResult.getPrincipal();
		// Create the algorithm used to sign the token, in this case we are using a symetric algorithm
		Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
		// Genereate the access Token using IWT library
		String jwtAccessToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.ACCESS_TOKEN_EXPIRES *60*1000))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles", user.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.toList()))
				.sign(algorithm);
		// Genereate the refresh token Token using IWT library
		String jwtRefreshToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtUtils.REFRESH_TOKEN_EXPIRES *60*1000))
				.sign(algorithm);
		Map<String, String> tokens = new HashMap<>();
		tokens.put("accessToken", jwtAccessToken);
		tokens.put("refreshToken", jwtRefreshToken);
		response.setContentType("application/json");
		response.setHeader("Authorization", jwtAccessToken);
		new ObjectMapper().writeValue(response.getOutputStream(), tokens);
	}
}
