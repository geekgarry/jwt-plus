package com.github.plusplus.jet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.plusplus.exceptions.InvalidClaimException;
import com.github.plusplus.exceptions.JWTCreationException;
import com.github.plusplus.exceptions.JWTVerificationException;
import com.github.plusplus.algorithm.Algorithm;
import com.github.plusplus.exceptions.SignatureGenerationException;
import com.github.plusplus.exceptions.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * author     : geekplus
 * email      :
 * date       : 10/1/24 1:33 PM
 * description: //TODO
 */
public class Jet {
    private static final String ALGORITHM = "AES";
    /**
     * AES加密的密钥，用来加密json web token
     */
    public static String SECRET_KEY = "9@#97plus*&$1jk7"; // 16/24/32 字符

    private Map<String, Object> header;
    private Map<String, Object> claims;

    private String secretKey;
    private Algorithm algorithm;

    // ObjectMapper for handling JSON objects
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private Jet(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.secretKey = builder.secretKey;
        this.algorithm = builder.algorithm;
    }

    // 静态方法，用于获取 Builder 实例
    public static Builder builder() {
        return new Builder();
    }

    // 静态方法，用于获取 JetVerifier 实例
    public static JetVerifier require() {
        return new JetVerifier();
    }

    // Builder 类，用于构建 Jet 实例
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
            this.claims.put("role", arrayToString(roles));
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

        //当前jet的id，用来表示唯一性
        public Builder withJetId(String id) {
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

        public Jet build() {
            return new Jet(this);
        }

        // 生成 Token
        public String sign() {
            // 如果头部为空，使用默认头部
            if (header == null || header.isEmpty()) {
                header = new HashMap<>();
                header.put("typ", "Jet");
            }
            if(algorithm == null){
                header.put("alg", "HS256");
            }else {
                header.put("alg", algorithm.getId());
            }
            // 对头部和载体进行 Base64 编码
            String headerEncoded = encrypt(mapToJson(header));
            String claimsEncoded = encrypt(mapToJson(claims));
            if(claimsJson !=null){
                claimsEncoded = encrypt(claimsJson);
            }

            // 生成签名
            String signature = new Jet(this).generateSignature(headerEncoded.getBytes(StandardCharsets.UTF_8), claimsEncoded.getBytes(StandardCharsets.UTF_8));
            // 合成最终的 Token
            return String.format("%s.%s.%s", headerEncoded, claimsEncoded, signature);
        }
    }

    // 生成 HMAC256 签名
    private String generateSignature(byte[] header, byte[] claims) {
        try {
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

    // 内部类 JetVerifier
    public static class JetVerifier {
        String secretKey = "plus#$&*geek!@*gl3478";

        private Algorithm algorithm = Algorithm.HMAC256("!ad#12~plus+asd!234ilovext");

        public JetVerifier secret(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public JetVerifier algorithm(Algorithm algorithm) {
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
            Map<String, Object> claims = jsonToMap(decrypt(claimsEncoded));

            if(claims.containsKey("ntb")) {
                String notBefore = claims.get("ntb").toString();
                //notBefore表示在此之前，jet都是不可用的
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

            String expectedSignature = Jet.builder()
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
            return jsonToMap(decrypt(claimsEncoded));
        }

        // 静态方法，用于获取 JetVerifier 实例
        public DecodeJet verify(String token) throws JWTVerificationException {
            if(!verifyValidToken(token)) {
                throw new JWTVerificationException("Token Verify Fail");
            }
            return new DecodeJet().verify(token);
        }
    }

    // 内部类 DecodeJet
    public static class DecodeJet {
        String token;

        String header;

        String payload;

        String signature;

        public DecodeJet verify(String token) throws InvalidClaimException{
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new InvalidClaimException("Invalid Token format");
            }

            String claimsEncoded = parts[1];
            this.header = parts[0];
            this.payload = decrypt(claimsEncoded);
            return this;
        }

        public Date getIssuedAt() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return getDateByTime(claims.get("iat").toString());
        }

        public Date getExpireAt() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return getDateByTime(claims.get("exp").toString());
        }

        public String getClaim(String name){
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get(name).toString();
        }

        //用户所属角色
        public String[] getRole() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return stringToArray(claims.get("role").toString());
        }

        //面向用户群体
        public String getSubject() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get("sub").toString();
        }

        //签发者
        public String getIssuer() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get("isr").toString();
        }

        //当前jet的id，用来表示唯一性或一次性jet
        public String getJetId() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get("jId").toString();
        }

        //key，可以是钥匙ID
        public String getKeyId() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get("kId").toString();
        }

        //接收方
        public String getAudience() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return claims.get("aud").toString();
        }

        //在该时间之前处于不可用的状态
        public Date getNotBefore() {
            Map<String, Object> claims = jsonToMap(this.payload);
            return getDateByTime(claims.get("ntb").toString());
        }
    }

    // 从 Token 中获取载体部分的方法
    public static Map<String, Object> getClaims(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new InvalidClaimException("Invalid Token format");
        }

        String claimsEncoded = parts[1];
        return jsonToMap(decrypt(claimsEncoded));
    }

    // Base64 编码
    private static String encodeBase64(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    // Base64 解码
    private static String decodeBase64(String data) {
        return new String(Base64.getUrlDecoder().decode(data), StandardCharsets.UTF_8);
    }

    // Map转JSON字符串
    private static String mapToJson(Map<String, Object> map) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTCreationException("string to json error", e);
        }
    }

    // JSON字符串转Map
    private static Map<String, Object> jsonToMap(String json) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTCreationException("json to string error", e);
        }
    }

    private static ObjectNode stringToJson(String JsonStr) {
        try {
            return (ObjectNode) objectMapper.readTree(JsonStr);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTCreationException("String to Json Fail!", e);
        }
    }

    // 将数组转换为字符串
    private static String arrayToString(String[] arrays) {
        // 使用String.join()方法将字符串数组转换成一个字符串
        // 使用空格作为分隔符
//        StringBuilder sb = new StringBuilder();
//        for (String number : arrays) {
//            sb.append(number).append(",");
//        }
//        String result = sb.toString();
        return String.join(",", arrays);
    }

    // 将字符串转换回数组
    private static String[] stringToArray(String arrayStr) {
        String[] pairs = arrayStr.split(",");
        String[] arrays = new String[pairs.length];
        for (int i = 0; i < pairs.length; i++) {
            arrays[i] = pairs[i];
        }
        return arrays;
    }

    private static Date getDateByStr(String dateTimeStr) {
        // 创建DateFormat对象
        DateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH);
        try {
            // 解析时间字符串
            Date date = dateFormat.parse(dateTimeStr);

            // 获取秒数
            return date;
        } catch (DateTimeParseException | ParseException | NullPointerException e) {
            throw new JWTCreationException("DateTime Parse Error or dateTimeStr is null", e);
        }
    }

    private static long getDateTimeByStr(String dateTimeStr){
        // 创建DateFormat对象
        DateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");
        try {
            // 解析时间字符串
            Date date = dateFormat.parse(dateTimeStr);

            // 获取秒数
            return date.getTime();
        } catch (DateTimeParseException | ParseException | NullPointerException e) {
            throw new JWTCreationException("DateTime Parse Error or dateTimeStr is null", e);
        }
    }

    private static Date getDateByTime(String dateTimeStr) {
        // 创建DateFormat对象
        long timeMill = Long.valueOf(dateTimeStr);
        try {
            // 解析时间字符串
            Date date = new Date(timeMill);
            // 获取秒数
            return date;
        } catch (DateTimeParseException | NullPointerException e) {
            throw new JWTCreationException("DateTime Parse Error or dateTimeStr is null", e);
        }
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
