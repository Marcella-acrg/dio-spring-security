package dio.dio_spring_security.repository;

import dio.dio_spring_security.model.UserApp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.userdetails.User;

public interface UserRepository extends JpaRepository<UserApp, Integer> {
    @Query("SELECT e FROM UserApp e JOIN FETCH e.roles WHERE e.username= (:username)")
    public UserApp findByUsername(@Param("username") String username);
}



