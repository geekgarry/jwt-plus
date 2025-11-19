package io.github.geekgarry.algorithm;

/**
 * author     : geekplus
 * email      :
 * date       : 10/1/24 9:54 AM
 * description: //TODO
 */
public class Algorithm {
    private String id;
    private String name;
    private String key;

    public Algorithm(String id, String name, String key) {
        this.id = id;
        this.name = name;
        this.key = key;
    }

    public static Algorithm HMAC1(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_SHA1.getId(), AlgorithmEnum.HMAC_SHA1.getName(), secret);
    }

    public static Algorithm HMAC224(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_SHA224.getId(), AlgorithmEnum.HMAC_SHA224.getName(), secret);
    }

    public static Algorithm HMAC256(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_SHA256.getId(), AlgorithmEnum.HMAC_SHA256.getName(), secret);
    }

    public static Algorithm HMAC384(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_SHA384.getId(), AlgorithmEnum.HMAC_SHA384.getName(), secret);
    }

    public static Algorithm HMAC512(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_SHA512.getId(), AlgorithmEnum.HMAC_SHA512.getName(), secret);
    }

    public static Algorithm HMACMd5(String secret) {
        return new Algorithm(AlgorithmEnum.HMAC_MD5.getId(), AlgorithmEnum.HMAC_MD5.getName(), secret);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getKey() {
        return key;
    }
}
