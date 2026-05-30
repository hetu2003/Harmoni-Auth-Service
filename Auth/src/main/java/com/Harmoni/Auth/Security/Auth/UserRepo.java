package com.Harmoni.Auth.Security.Auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<Users, Long> {
    // 1. Used by Google/Gmail login to see if the user already exists
    @Query("SELECT u FROM Users u WHERE u.email = :email")
    Users findByEmail(@Param("email") String email);

    // 2. Used by CustomUserDetailsService for traditional password login
    @Query("SELECT u FROM Users u WHERE u.username = :username")
    Users findByUsername(@Param("username") String username);

    // 3. Optional helper for checking registration status safely
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM Users u WHERE u.email = :email")
    boolean existsByEmail(@Param("email") String email);

    @Query(value = "select count(*) from Users where email = :email", nativeQuery = true)
    Integer findEmailCount(@Param("email") String email);
}
