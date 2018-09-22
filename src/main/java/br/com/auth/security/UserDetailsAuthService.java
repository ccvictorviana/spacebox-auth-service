package br.com.auth.security;

import br.com.auth.domain.User;
import br.com.auth.repository.UserRepository;
import br.com.spacebox.common.exceptions.BusinessException;
import br.com.spacebox.common.security.UserDetailsAuth;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsAuthService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(login);

        if (user == null) {
            throw new BusinessException("User '" + login + "' not found");
        }

        return UserDetailsAuth
                .getBuilder()
                .withUsername(login)
                .withPassword(user.getPassword())
                .withAccountExpired(false)
                .withAccountLocked(false)
                .withCredentialsExpired(false)
                .withDisabled(false)
                .withId(user.getId())
                .withName(user.getName())
                .withEmail(user.getEmail())
                .build();
    }

}
