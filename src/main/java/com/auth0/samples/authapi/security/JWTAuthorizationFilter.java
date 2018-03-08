package com.auth0.samples.authapi.security;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		final String header = request.getHeader(SecurityConstants.HEADER_STRING);

		if (header != null && header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			SecurityContextHolder.getContext().setAuthentication(getAuthentication(header));
		}

		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(String authenticationHeader) {
		// Parse the JWT header
		String user = Jwts.parser()
				.setSigningKey(SecurityConstants.SECRET.getBytes())
				.parseClaimsJws(authenticationHeader.replace(SecurityConstants.TOKEN_PREFIX, ""))
				.getBody()
				.getSubject();

		return Optional.ofNullable(user)
				.map(u -> new UsernamePasswordAuthenticationToken(u, null, Collections.emptyList()))
				.orElse(null);
	}
}
