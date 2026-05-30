package com.Harmoni.Auth.Security.config.UserDetails;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSecurityDetailRepo extends JpaRepository<UserSecurityDetails, Integer> {

    @Query(value = "select user from UserSecurityDetails user where user.userid = :userid and active != 9")
    UserSecurityDetails findbyUserId(@Param("userid") String userid);
}
