package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// 토큰 발급이 필요하다. ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 발행하고, 해당 토큰을 응답한다.
		// 요청 시 header에 Authorization 의 value 값으로 해당 토큰이 들어온다.
		// 토큰이 내가 만든 토큰이 맞는지 검증한다. (RSA, HS256)
		/*if ("POST".equals(req.getMethod())) {
			String authorization = req.getHeader("Authorization");
			
			if ("token".equals(authorization)) {
				chain.doFilter(req, res);
			} else {
				PrintWriter out = res.getWriter();
				out.print("Not Authorization");
			}
		} else {
			chain.doFilter(request, response);
		}*/
		chain.doFilter(request, response);
	}
}
