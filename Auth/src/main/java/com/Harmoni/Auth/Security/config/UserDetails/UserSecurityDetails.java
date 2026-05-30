package com.Harmoni.Auth.Security.config.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.Date;

@Entity
public class UserSecurityDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    private String userid;
    private String token;
    private String syckey;
    private Date cretadetime;
    private Date expiretime;
    private int active = 1;

    public UserSecurityDetails() {
    }

    public UserSecurityDetails(int id, String userid, String token, String syckey, Date cretadetime,
                               Date expiretime, int active) {
        super();
        this.id = id;
        this.userid = userid;
        this.token = token;
        this.syckey = syckey;
        this.cretadetime = cretadetime;
        this.expiretime = expiretime;
        this.active = active;
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUserId() {
        return userid;
    }

    public void setUserId(String userid) {
        this.userid = userid;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUserid() {
        return userid;
    }

    public void setUserid(String userid) {
        this.userid = userid;
    }

    public String getSyckey() {
        return syckey;
    }

    public void setSyckey(String syckey) {
        this.syckey = syckey;
    }

    public Date getCretadetime() {
        return cretadetime;
    }

    public void setCretadetime(Date cretadetime) {
        this.cretadetime = cretadetime;
    }

    public Date getExpiretime() {
        return expiretime;
    }

    public void setExpiretime(Date expiretime) {
        this.expiretime = expiretime;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }
}

