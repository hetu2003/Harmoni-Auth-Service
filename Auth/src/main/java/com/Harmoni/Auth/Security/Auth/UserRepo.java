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

    // 3. Used for password reset functionality
    @Query("SELECT u FROM Users u WHERE u.resetPasswordToken = :token")
    Users findByResetPasswordToken(@Param("token") String token);
}
