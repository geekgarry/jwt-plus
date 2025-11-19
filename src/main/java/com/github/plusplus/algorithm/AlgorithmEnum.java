package com.github.plusplus.algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * author     : geekplus
 * email      : geekcjj@gmail.com
 * date       : 10/1/24 9:55 AM
 * description: 做什么的？
 */
public enum AlgorithmEnum {
    HMAC_SHA1("HS1", "HmacSHA1"),
    HMAC_SHA224("HS224", "HmacSHA224"),
    HMAC_SHA256("HS256", "HmacSHA256"),
    HMAC_SHA512("HS512", "HmacSHA512"),
    HMAC_SHA384("HS384", "HmacSHA384"),
    HMAC_MD5("HMd5", "HmacMD5");

    private final String id;
    private final String name;

    AlgorithmEnum(String id, String algorithmName) {
        this.id = id;
        this.name = algorithmName;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    /**
     * 使用指定算法对数据进行签名
     *
     * @param data      要加密的数据
     * @param secretKey 密钥
     * @return 签名后的数据
     */
    public String sign(String data, String secretKey) {
        try {
            Mac mac = Mac.getInstance(name);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), name);
            mac.init(secretKeySpec);
            byte[] signedBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error while signing data with " + name, e);
        }
    }
}
