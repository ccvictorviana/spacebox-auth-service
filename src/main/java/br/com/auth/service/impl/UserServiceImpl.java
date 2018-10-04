package br.com.auth.service.impl;

import br.com.auth.repository.UserRepository;
import br.com.auth.security.JwtTokenProvider;
import br.com.auth.service.UserService;
import br.com.spacebox.common.domain.User;
import br.com.spacebox.common.exceptions.BusinessException;
import br.com.spacebox.common.messages.EMessage;
import br.com.spacebox.common.model.response.TokenResponse;
import br.com.spacebox.common.security.PrincipalToken;
import br.com.spacebox.common.security.UserDetailsAuth;
import br.com.spacebox.common.service.AEntityService;
import br.com.spacebox.common.service.ValidationType;
import br.com.spacebox.common.validation.FluentValidationString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class UserServiceImpl extends AEntityService<User> implements UserService {
    @Autowired
    private UserRepository repository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void create(User user) {
        validate(ValidationType.CREATE, user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        repository.save(user);
    }

    @Override
    public void update(UserDetailsAuth auth, User user) {
        user.setId(auth.getId());
        validate(ValidationType.UPDATE, user);
        repository.update(user.getName(), user.getEmail(), auth.getUsername());
    }

    @Override
    public User find(String userName) {
        return repository.findByUsername(userName);
    }

    @Override
    public void delete(UserDetailsAuth auth) {
        repository.deleteByUsername(auth.getUsername());
    }

    @Override
    public TokenResponse login(String login, String password) {
        try {
            authenticationManager.authenticate(new PrincipalToken(login, password));
            return jwtTokenProvider.createToken(login);
        } catch (AuthenticationException e) {
            throw new BusinessException(getMessage(EMessage.INVALID_LOGIN));
        }
    }

    @Override
    public void logout(String userName) {
        repository.saveToken(userName, null, null);
    }

    @Override
    public void saveToken(String login, String token, Date expirationDate) {
        repository.saveToken(login, token, expirationDate);
    }

    @Override
    public boolean existsToken(String token) {
        Date dateNow = new Date();
        return repository.existsToken(token, dateNow);
    }

    @Override
    protected void onValidate(ValidationType type, User user, List<String> errors) {
        User userDB;

        FluentValidationString.notNullAndEmpty().test(user.getName()).addMessage(getMessage(EMessage.REQUIRED_FIELD_NAME), errors);
        FluentValidationString.notNullAndEmpty().test(user.getEmail()).addMessage(getMessage(EMessage.REQUIRED_FIELD_EMAIL), errors);
        FluentValidationString.notNullAndEmpty().test(user.getUsername()).addMessage(getMessage(EMessage.REQUIRED_FIELD_LOGIN), errors);

        if (type == ValidationType.CREATE) {
            FluentValidationString.notNullAndEmpty().test(user.getPassword()).addMessage(getMessage(EMessage.REQUIRED_FIELD_PASSWORD), errors);
        }

        if (user.getUsername() != null) {
            userDB = repository.findByUsername(user.getUsername());
            if (userDB != null && !userDB.getId().equals(user.getId())) {
                errors.add(getMessage(EMessage.ALREADYEXISTS_LOGIN));
            }
        }

        if (user.getEmail() != null) {
            userDB = repository.findByEmail(user.getEmail());
            if (userDB != null && !userDB.getId().equals(user.getId())) {
                errors.add(getMessage(EMessage.ALREADYEXISTS_EMAIL));
            }
        }
    }
}
