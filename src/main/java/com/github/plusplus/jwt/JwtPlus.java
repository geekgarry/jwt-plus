package com.github.plusplus.jwt;

import com.github.plusplus.algorithm.Algorithm;
import com.github.plusplus.exceptions.InvalidClaimException;
import com.github.plusplus.exceptions.JWTDecodeException;
import com.github.plusplus.exceptions.JWTVerificationException;
import com.github.plusplus.exceptions.SignatureGenerationException;
import com.github.plusplus.util.EnTokenUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * author     : geekplus
 * email      :
 * date       : 10/1/24 1:33 PM
 * description: //TODO
 */
public class JwtPlus {

    private Map<String, Object> header;
    private Map<String, Object> claims;

    private String secretKey;
    private Algorithm algorithm;

    private JwtPlus(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.secretKey = builder.secretKey;
        this.algorithm = builder.algorithm;
    }

    // 静态方法，用于获取 Builder 实例
    public static Builder builder() {
        return new Builder();
    }

    // 静态方法，用于获取 JwtVerifier 实例
    public static JwtVerifier require() {
        return new JwtVerifier();
    }

    // Builder 类，用于构建 JwtPlus 实例
    public static class Builder {

        Map<String, Object> header = new HashMap<>();
        Map<String, Object> claims = new HashMap<>();
        String claimsJson = null;

        String secretKey = "plus#$&*geek!@*gl3478";

        private Algorithm algorithm = Algorithm.HMAC256("!ad#12~plus+asd!234ilovext");

        public Builder withHeader(Map<String, Object> header) {
            this.header = header;
            return this;
        }

        public Builder claim(String key, String value) {
            this.claims.put(key, value);
            return this;
        }

        public Builder withPayload(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        public Builder withPayload(String payloadJson) {
            this.claimsJson = payloadJson;
            return this;
        }

        //用户所属角色
        public Builder withRole(String[] roles) {
            this.claims.put("role", EnTokenUtil.arrayToString(roles));
            return this;
        }

        //面向用户群体
        public Builder withSubject(String subject) {
            this.claims.put("sub", subject);
            return this;
        }

        //签发者
        public Builder withIssuer(String issuer) {
            this.claims.put("isr", issuer);
            return this;
        }

        //当前jwt的id，用来表示唯一性
        public Builder withJwtId(String id) {
            this.claims.put("jId", id);
            return this;
        }

        //key，可以是钥匙ID
        public Builder withKeyId(String id) {
            this.claims.put("kId", id);
            return this;
        }

        //接收方
        public Builder withAudience(String audience) {
            this.claims.put("aud", audience);
            return this;
        }

        //在该时间之前处于不可用的状态
        public Builder withNotBefore(Date dateTime) {
            this.claims.put("ntb", dateTime.getTime());
            return this;
        }

        public Builder issuedAt(Date dateTime) {
            this.claims.put("iat", dateTime.getTime());
            return this;
        }

        public Builder expireAt(Date dateTime) {
            this.claims.put("exp", dateTime.getTime());
            return this;
        }

        public Builder algorithm(Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder secret(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public JwtPlus build() {
            return new JwtPlus(this);
        }

        // 生成 Token
        public String sign() {
            // 如果头部为空，使用默认头部
            if (header == null || header.isEmpty()) {
                header = new HashMap<>();
                header.put("typ", "Jwt");
            }
            if(algorithm == null){
                header.put("alg", "HS256");
            }else {
                header.put("alg", algorithm.getId());
            }
            // 对头部和载体进行 Base64 编码
            String headerEncoded = EnTokenUtil.encodeBase64(EnTokenUtil.mapToJson(header));
            String claimsEncoded = EnTokenUtil.encodeBase64(EnTokenUtil.mapToJson(claims));
            if(claimsJson !=null){
                claimsEncoded = EnTokenUtil.encodeBase64(claimsJson);
            }

            // 生成签名
            String signature = new JwtPlus(this).generateSignature(headerEncoded.getBytes(StandardCharsets.UTF_8), claimsEncoded.getBytes(StandardCharsets.UTF_8));
            // 合成最终的 Token
            return String.format("%s.%s.%s", headerEncoded, claimsEncoded, signature);
        }
    }

    // 生成 HMAC256 签名
    private String generateSignature(byte[] header, byte[] claims) {
        try {
            Mac mac;
            SecretKeySpec secretKeySpec;
            if(algorithm == null) {
                mac = Mac.getInstance("HmacSHA256");
                secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            }else {
                mac = Mac.getInstance(algorithm.getName());
                secretKeySpec = new SecretKeySpec(algorithm.getKey().getBytes(StandardCharsets.UTF_8), algorithm.getName());
            }
            mac.init(secretKeySpec);
            byte[] contentBytes = new byte[header.length + 1 + claims.length];
            System.arraycopy(header, 0, contentBytes, 0, header.length);
            contentBytes[header.length] = 46;
            System.arraycopy(claims, 0, contentBytes, header.length + 1, claims.length);
            byte[] signatureBytes = mac.doFinal(contentBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            //"Error generating HMAC256 signature"
            throw new SignatureGenerationException(algorithm, e);
        }
    }

    // 内部类 JwtVerifier
    public static class JwtVerifier {
        String secretKey = "plus#$&*geek!@*gl3478";

        private Algorithm algorithm = Algorithm.HMAC256("!ad#12~plus+asd!234ilovext");

        public JwtVerifier secret(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public JwtVerifier algorithm(Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public boolean verifyValidToken(String token) {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            String headerEncoded = parts[0];
            String claimsEncoded = parts[1];
            String signature = parts[2];

            // 解码并验证载体
            Map<String, Object> claims = EnTokenUtil.jsonToMap(EnTokenUtil.decodeBase64(claimsEncoded));
            String notBefore;

            if(claims.containsKey("ntb")) {
                notBefore = claims.get("ntb").toString();
                //notBefore表示在此之前，jwt都是不可用的
                if(notBefore != null && System.currentTimeMillis() < Long.valueOf(notBefore)) {
                    return false;
                }
            }

            if(claims.containsKey("exp")) {
                String expireTime = claims.get("exp").toString();
                //如果expireTime不为空，且当前时间大于expireTime，表示过期
                if (expireTime != null && System.currentTimeMillis() > Long.valueOf(expireTime)) {
                    return false;
                }
            }

            String expectedSignature = JwtPlus.builder()
                    .withPayload(new HashMap<>()) // 空 claims 仅用于签名
                    .secret(secretKey)
                    .algorithm(algorithm)
                    .build()
                    .generateSignature(headerEncoded.getBytes(StandardCharsets.UTF_8), claimsEncoded.getBytes(StandardCharsets.UTF_8));

            return expectedSignature.equals(signature);
        }

        public Map<String, Object> getClaims(String token) throws InvalidClaimException {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new InvalidClaimException("Invalid Token format");
            }

            String claimsEncoded = parts[1];
            return EnTokenUtil.jsonToMap(EnTokenUtil.decodeBase64(claimsEncoded));
        }

        // 静态方法，用于获取 JwtVerifier 实例
        public DecodeJwt verify(String token){
            if(!verifyValidToken(token)) {
                throw new JWTDecodeException("Token Verify Fail");
            }
            return new DecodeJwt().verify(token);
        }
    }

    // 内部类 DecodeJwt
    public static class DecodeJwt {
        String token;

        String header;

        String payload;

        String signature;

        public DecodeJwt verify(String token) {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new JWTVerificationException("Invalid Token format");
            }

            String claimsEncoded = parts[1];
            this.header = parts[0];
            this.payload = EnTokenUtil.decodeBase64(claimsEncoded);
            return this;
        }

        public Date getIssuedAt() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("iat").toString());
        }

        public Date getExpireAt() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("exp").toString());
        }

        public String getClaim(String name){
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get(name).toString();
        }

        //用户所属角色
        public String[] getRole() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return EnTokenUtil.stringToArray(claims.get("role").toString());
        }

        //面向用户群体
        public String getSubject() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get("sub").toString();
        }

        //签发者
        public String getIssuer() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get("isr").toString();
        }

        //当前jwt的id，用来表示唯一性或一次性jwt
        public String getJwtId() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get("jId").toString();
        }

        //key，可以是钥匙ID
        public String getKeyId() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get("kId").toString();
        }

        //接收方
        public String getAudience() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return claims.get("aud").toString();
        }

        //在该时间之前处于不可用的状态
        public Date getNotBefore() {
            Map<String, Object> claims = EnTokenUtil.jsonToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("ntb").toString());
        }
    }

    // 从 Token 中获取载体部分的方法
    public static Map<String, Object> getClaims(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new InvalidClaimException("Invalid Token format");
        }

        String claimsEncoded = parts[1];
        return EnTokenUtil.jsonToMap(EnTokenUtil.decodeBase64(claimsEncoded));
    }
}
