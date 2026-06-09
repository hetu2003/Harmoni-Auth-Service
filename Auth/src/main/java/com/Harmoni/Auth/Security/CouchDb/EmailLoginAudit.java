package com.Harmoni.Auth.Security.CouchDb;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailLoginAudit {

    @SerializedName("_id")
    private String id;

    @SerializedName("_rev")
    private String rev;

    private String email;
    private String type;       // "EMAIL_OTP_SEND" | "EMAIL_OTP_VERIFY_SUCCESS" | "EMAIL_OTP_VERIFY_FAIL"
    private String status;     // "SUCCESS" | "FAILED"
    private String timestamp;
    private String userId;
    private String message;
}
