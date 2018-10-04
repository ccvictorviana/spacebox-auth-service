package br.com.auth.security;

import br.com.auth.service.UserService;
import br.com.spacebox.common.domain.User;
import br.com.spacebox.common.model.response.TokenResponse;
import br.com.spacebox.common.security.PrincipalToken;
import br.com.spacebox.common.security.UserDetailsAuth;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
    @Value("${security.jwt.token.secret-key:secret-key}")
    private String tokenSecretKey;

    @Value("${security.jwt.token.expire-length}")
    private long tokenExpiration;

    @Value("${security.jwt.token.type}")
    private String tokenType;

    @Autowired
    private UserDetailsAuthService myUserDetails;

    @Autowired
    private UserService userService;

    @PostConstruct
    protected void init() {
        tokenSecretKey = Base64.getEncoder().encodeToString(tokenSecretKey.getBytes());
    }

    public TokenResponse createToken(String username) {
        Date now = new Date();
        User user = userService.find(username);
        Date validity = new Date(now.getTime() + tokenExpiration);
        String tokenAccess;

        if (isTokenExpired(user)) {
            int safeTimeBetweenDbAndToken = 9000;
            Claims claims = Jwts.claims().setSubject(username);
            tokenAccess = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(now)
                    .setExpiration(new Date(validity.getTime() + safeTimeBetweenDbAndToken))
                    .signWith(SignatureAlgorithm.HS256, tokenSecretKey)
                    .compact();
        } else {
            tokenAccess = user.getToken();
        }

        userService.saveToken(username, tokenAccess, validity);

        TokenResponse token = new TokenResponse();
        token.setToken(tokenAccess);
        token.setExpiration(validity.getTime());
        token.setType(tokenType);

        return token;
    }

    private boolean isTokenExpired(User user) {
        boolean result = true;

        if (user.getToken() != null) {
            try {
                Jwts.parser().setSigningKey(tokenSecretKey).parseClaimsJws(user.getToken());
                Date dateNow = new Date();
                result = user.getTokenExpiration() != null && dateNow.after(user.getTokenExpiration());
            } catch (ExpiredJwtException ex) {
            }
        }

        return result;
    }

    public Authentication getAuthentication(String token) {
        UserDetailsAuth userDetails = (UserDetailsAuth) myUserDetails.loadUserByUsername(getUsername(token));
        return new PrincipalToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(tokenSecretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith(tokenType + " ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        return userService.existsToken(token);
    }
}
