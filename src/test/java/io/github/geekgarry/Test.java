package io.github.geekgarry;

import io.github.geekgarry.algorithm.Algorithm;
import io.github.geekgarry.jwt.JwtPlus;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * author     : geekplus
 * email      :
 * date       : 10/1/24 9:56 AM
 * description: //TODO
 */
public class Test {
    public static void main(String[] args) {
        // 自定义头部和载体生成Token
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("userName","dsjjdsjk");
        claims.put("tokenId","snfjasnfjnasjkbfajksb32423532b52");

        Algorithm algorithm = Algorithm.HMAC256("sjfjkbjfksbjfkbsjbfjks");
//        JwtPlus.SECRET_KEY = "2@#uhchan*&$1xt8";
        String token = JwtPlus.builder()
                .withPayload(claims)
                .expireAt(new Date(System.currentTimeMillis() + 5000))
                .issuedAt(new Date())
                .algorithm(algorithm)
                .sign();
        System.out.println("Generated Token: ");
        System.out.println(token);
//        "Generated Token: ZRafe8lJTXvwsz3oFNHIUZlaSIN0yzjJvOdj12n+2ss=.2IE7f0aTiOJRN9zKGsckWld3FzLnc01PVUrVs0Mzn5OwuXaDlsv/LnnS0kbQT8/NyOT35zO1Cq1DWtiTfwymGfhV4sv2omIsIypSqI2e+cobKuDx8nUYeHcSckIpPNQ2UfPSN3cSP9lddN8TDUiWRabAZVgbkxSt+Ded1V9vJNw=.fA8iEmjHdgT98Thr/J05FqmPN3qRPdtOvkfig1g13evpeg6WkjO4qtz0O0rgsjz5HznAWLZTVvqrHnab6QiNK7WWLhOHElMFdC9hPHW7Tgs="
        // 验证 Token
        boolean isValid = JwtPlus.require().algorithm(algorithm).verifyValidToken(token);
        System.out.println("Is Token valid? " + isValid);

        // 从 Token 中获取载体内容
        Map<String, Object> payload = JwtPlus.require().secret("urhgesnkdngknkdsngk548y6480").getClaims(token);
        JwtPlus.JwtVerifier jwtVerifier = JwtPlus.require().algorithm(algorithm);
        JwtPlus.DecodeJwt decodeJwt = jwtVerifier.verify(token);
        System.out.println("IssueAt: " + decodeJwt.getIssuedAt());
        System.out.println("Claims: " + decodeJwt.getExpireAt());
        System.out.println("Claims: " + decodeJwt.getClaim("userName"));
        // 模拟 Token 过期后验证
        try {
            Thread.sleep(6000); // 模拟超过1小时
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        boolean isExpired = JwtPlus.require().verifyValidToken(token);
        System.out.println(new Date());
        System.out.println("Is Token valid? " + isExpired);
    }
}
