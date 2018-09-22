package br.com.auth.service;

import br.com.auth.domain.User;
import br.com.spacebox.common.model.response.TokenResponse;
import br.com.spacebox.common.security.UserDetailsAuth;

import java.util.Date;

public interface UserService {
    void create(User user);

    void delete(UserDetailsAuth auth);

    User find(String userName);

    void update(UserDetailsAuth auth, User user);

    TokenResponse login(String login, String password);

    void logout(String userName);

    void saveToken(String login, String token, Date expirationDate);

    boolean existsToken(String token);
}