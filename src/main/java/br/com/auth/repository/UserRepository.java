package br.com.auth.repository;

import br.com.spacebox.common.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.Date;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);

    User findByUsername(String userName);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.name = ?1, u.email = ?2 WHERE u.username = ?3")
    void update(String name, String email, String login);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.token = ?2, u.tokenExpiration = ?3 WHERE u.username = ?1")
    void saveToken(String login, String token, Date tokenExpiration);

    @Query("SELECT case when (count(u) > 0) then true else false end FROM User u WHERE u.token = ?1 AND u.tokenExpiration >= ?2")
    boolean existsToken(String token, Date currentDate);

    @Transactional
    void deleteByUsername(String login);
}