package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

// 시큐리티가 가지고 있는 필터 중 BasicAuthenticationFilter 라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때, 해당 필터를 무조건 타게 되어있다.
// 만약 권한이나 인증이 피요한 주소가 아니라면 해당 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	private final UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		System.out.println("## 권한 또는 인증이 필요한 요청");
		
		String auth_header = request.getHeader("Authorization");
		System.out.println("## auth_header: " + auth_header);
		
		if (auth_header == null || !auth_header.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		String token = request.getHeader("Authorization").replace("Bearer ", "");
		String username = JWT.require(Algorithm.HMAC256("TOKEN_SECRET"))
				.build()
				.verify(token)
				.getClaim("username")
				.asString();
		
		if (username != null) {
			User user = userRepository.findByUsername(username)
					.orElseThrow(() -> new IllegalArgumentException("사용자 정보가 유효히지 않습니다."));
			
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
	}
}
