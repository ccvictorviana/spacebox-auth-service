package br.com.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends GenericFilterBean {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        if (!isAllowedWithoutToken(req)) {
            String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
            if (token != null && jwtTokenProvider.validateToken(token)) {
                Authentication auth = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
                filterChain.doFilter(req, res);
            } else {
                ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } else {
            filterChain.doFilter(req, res);
        }
    }

    private boolean isAllowedWithoutToken(ServletRequest servletRequest) {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        String uri = req.getRequestURI();
        String uriLowerCase = uri.toLowerCase();
        boolean isRegisterUserRequest = (uriLowerCase.endsWith("/users/") && req.getMethod().equalsIgnoreCase("POST"));

        return (uriLowerCase.endsWith("/users/login") || (uriLowerCase.endsWith("/users/") && isRegisterUserRequest));
    }
}