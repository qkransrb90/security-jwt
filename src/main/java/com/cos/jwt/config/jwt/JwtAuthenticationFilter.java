package com.cos.jwt.config.jwt;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		System.out.println("##attemptAuthentication");
		
		// 1. username, password를 받아서
		// 2. 정상인지 로그인 시도 (AuthenticationManager -> PrincipalDetailsService 의 loadUserByName() 호출)
		// 3. PrincipalDetails를 세션에 담는다. (권한 관리를 위함)
		// 4. JWT 토큰을 만들어 발급한다.
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			User user = objectMapper.readValue(request.getInputStream(), User.class);
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			Authentication authentication = authenticationManager.authenticate(token);
			
			return authentication;
		} catch(Exception e) {
			System.out.println("Error: " + e.getMessage());
		}
		
		return null;
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		String jwtToken = JWT.create()
				.withSubject("auth_token")
				.withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC256("TOKEN_SECRET"));
		
		response.addHeader("Authorization", "Bearer " + jwtToken);
	}
}
