package com.app.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtAuthorizationFilter extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String authorizationToken = request.getHeader("Authorization");
		if(request.getServletPath().equals("/api/v1/refreshToken")) {
			filterChain.doFilter(request, response);
		}else {
			if(authorizationToken != null && authorizationToken.startsWith("Bearer ")) {
				try {
					String jwt = authorizationToken.substring(7);
					Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
					JWTVerifier verifier = JWT.require(algorithm).build();
					DecodedJWT decodedJWT = verifier.verify(jwt);
					String username = decodedJWT.getSubject();
					String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
					List<GrantedAuthority> authorities = new ArrayList<>();
					for(String role : roles)
						authorities.add(new SimpleGrantedAuthority(role));
					
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					filterChain.doFilter(request, response);
				}catch(Exception exception) {
					response.setHeader("error-message", exception.getMessage());
					response.sendError(403);
				}
			}else {
				filterChain.doFilter(request, response);
			}
		}
		
	}

}
