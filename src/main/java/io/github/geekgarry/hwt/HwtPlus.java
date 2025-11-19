package io.github.geekgarry.hwt;

import io.github.geekgarry.exceptions.InvalidClaimException;
import io.github.geekgarry.exceptions.JWTVerificationException;
import io.github.geekgarry.algorithm.Algorithm;
import io.github.geekgarry.util.EnTokenUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * author     : geekplus
 * email      :
 * date       : 10/1/24 9:51 AM
 * description: //TODO
 */
public class HwtPlus {
    private static final String ALGORITHM = "AES";
    /**
     * AES加密的密钥，用来加密json web token
     */
    public static String SECRET_KEY = "9@#97plus*&$1jk7"; // 16/24/32 字符

    private Map<String, String> header;
    private Map<String, String> claims;
    private String secretKey;
    private Algorithm algorithm;

    private HwtPlus(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.secretKey = builder.secretKey;
        this.algorithm = builder.algorithm;
    }

    // 静态方法，用于获取 Builder 实例
    public static Builder builder() {
        return new Builder();
    }

    // 静态方法，用于获取 HwtVerifier 实例
    public static HwtVerifier require() {
        return new HwtVerifier();
    }

    // Builder 类，用于构建 HwtPlus 实例
    public static class Builder {
        Map<String, String> header = new HashMap<>();
        Map<String, String> claims = new HashMap<>();

        String secretKey = "plus#$&*geek!@*gl3478";

        private Algorithm algorithm = Algorithm.HMAC256("!ad#12~plus+asd!234ilovext");

        public Builder withHeader(Map<String, String> header) {
            this.header.putAll(header);
            return this;
        }

        public Builder claim(String key, String value) {
            this.claims.put(key, value);
            return this;
        }

        public Builder withPayload(Map<String, String> claims) {
            this.claims.putAll(claims);
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
            this.claims.put("ntb", String.valueOf(dateTime.getTime()));
            return this;
        }

        public Builder issuedAt(Date dateTime) {
            this.claims.put("iat", String.valueOf(dateTime.getTime()));
            return this;
        }

        public Builder expireAt(Date dateTime) {
            this.claims.put("exp", String.valueOf(dateTime.getTime()));
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

        public HwtPlus build() {
            return new HwtPlus(this);
        }

        // 生成 Token
        public String sign() {
            // 如果头部为空，使用默认头部
            if (header == null || header.isEmpty()) {
                header = new HashMap<>();
                header.put("typ", "Hwt");
            }
            if(algorithm == null){
                header.put("alg", "HS256");
            }else {
                header.put("alg", algorithm.getId());
            }

            // 对头部和载体进行 Base64 编码
            String headerEncoded = encrypt(EnTokenUtil.mapToString(header));
            String claimsEncoded = encrypt(EnTokenUtil.mapToString(claims));

            // 生成签名
            String signature = new HwtPlus(this).generateSignature(headerEncoded, claimsEncoded);

            // 合成最终的 Token
            return String.format("%s.%s.%s", headerEncoded, claimsEncoded, signature);
        }
    }

    // 生成 HMAC256 签名
    private String generateSignature(String header, String claims) {
        try {
            String data = header + "." + claims;
            Mac mac;
            SecretKeySpec secretKeySpec;
            if(algorithm == null){
                mac = Mac.getInstance("HmacSHA256");
                secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            }else {
                mac = Mac.getInstance(algorithm.getName());
                secretKeySpec = new SecretKeySpec(algorithm.getKey().getBytes(StandardCharsets.UTF_8), algorithm.getName());
            }
            mac.init(secretKeySpec);
            byte[] signatureBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error generating HMAC256 signature", e);
        }
    }

    // 内部类 HwtVerifier
    public static class HwtVerifier {
        String secretKey = "plus#$&*geek!@*gl3478";

        private Algorithm algorithm = Algorithm.HMAC256("!ad#12~plus+asd!234ilovext");

        public HwtVerifier secret(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public HwtVerifier algorithm(Algorithm algorithm) {
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
            Map<String, String> claims = EnTokenUtil.stringToMap(decrypt(claimsEncoded));
            if(claims.containsKey("ntb")) {
                String notBefore = claims.get("ntb");
                //notBefore表示在此之前，jwt都是不可用的
                if(notBefore != null && System.currentTimeMillis() < Long.valueOf(notBefore)) {
                    return false;
                }
            }

            if(claims.containsKey("exp")) {
                String expireTime = claims.get("exp");
                //如果expireTime不为空，且当前时间大于expireTime，表示过期
                if (expireTime != null && System.currentTimeMillis() > Long.valueOf(expireTime)) {
                    return false;
                }
            }

            String expectedSignature = HwtPlus.builder()
                    .withPayload(new HashMap<>()) // 空 claims 仅用于签名
                    .secret(secretKey)
                    .algorithm(algorithm)
                    .build()
                    .generateSignature(headerEncoded, claimsEncoded);

            return expectedSignature.equals(signature);
        }

        public Map<String, String> getClaims(String token) throws InvalidClaimException {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new InvalidClaimException("Invalid Token format");
            }

            String claimsEncoded = parts[1];
            return EnTokenUtil.stringToMap(decrypt(claimsEncoded));
        }

        // 静态方法，用于获取 HwtVerifier 实例
        public DecodeHwt verify(String token) throws JWTVerificationException {
            if(!verifyValidToken(token)) {
                throw new JWTVerificationException("Token Verify Fail");
            }
            return new DecodeHwt().verify(token);
        }
    }

    // 内部类 DecodeHwt
    public static class DecodeHwt {
        String token;

        String header;

        String payload;

        String signature;

        public DecodeHwt verify(String token) {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid Token format");
            }

            String claimsEncoded = parts[1];
            this.header = parts[0];
            this.payload = decrypt(claimsEncoded);
            return this;
        }

        public Date getIssuedAt(){
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("iat"));
        }

        public Date getExpireAt(){
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("exp"));
        }

        public String getClaim(String name){
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get(name);
        }

        //用户所属角色
        public String[] getRole() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return EnTokenUtil.stringToArray(claims.get("role"));
        }

        //面向用户群体
        public String getSubject() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get("sub");
        }

        //签发者
        public String getIssuer() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get("isr");
        }

        //当前jwt的id，用来表示唯一性或一次性jwt
        public String getJwtId() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get("jId");
        }

        //key，可以是钥匙ID
        public String getKeyId() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get("kId");
        }

        //接收方
        public String getAudience() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return claims.get("aud");
        }

        //在该时间之前处于不可用的状态
        public Date getNotBefore() {
            Map<String, String> claims = EnTokenUtil.stringToMap(this.payload);
            return EnTokenUtil.getDateByTime(claims.get("ntb"));
        }
    }

    // 从 Token 中获取载体部分的方法
    public static Map<String, String> getClaims(String token) throws InvalidClaimException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new InvalidClaimException("Invalid Token format");
        }

        String claimsEncoded = parts[1];
        return EnTokenUtil.stringToMap(decrypt(claimsEncoded));
    }

    // 加密
    public static String encrypt(String data) {
        try{
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        }catch (Exception e){
            return data;
        }
    }

    // 解密
    public static String decrypt(String encryptedData) {
        try{
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedData = Base64.getDecoder().decode(encryptedData);
            byte[] originalData = cipher.doFinal(decodedData);
            return new String(originalData);
        }catch (Exception e){
            return encryptedData;
        }
    }
}
