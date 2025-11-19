package com.github.plusplus.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.plusplus.exceptions.JWTVerificationException;

import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * author     : geekplus
 * email      :
 * date       : 10/16/24 12:07 AM
 * description: //TODO
 */
public class EnTokenUtil {

    // ObjectMapper for handling JSON objects
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // Base64 编码
    public static String encodeBase64(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    // Base64 解码
    public static String decodeBase64(String data) {
        return new String(Base64.getUrlDecoder().decode(data), StandardCharsets.UTF_8);
    }

    // 将HashMap转换为字符串
    public static String mapToString(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            sb.append(entry.getKey()).append("=").append(entry.getValue()).append(";");
        }
        return sb.toString();
    }

    // 将字符串转换回HashMap
    public static Map<String, String> stringToMap(String token) {
        Map<String, String> map = new HashMap<>();
        String[] pairs = token.split(";");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                map.put(keyValue[0], keyValue[1]);
            }
        }
        return map;
    }

    // Map转JSON字符串
    public static String mapToJson(Map<String, Object> map) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTVerificationException("string to json error");
        }
    }

    // JSON字符串转Map
    public static Map<String, Object> jsonToMap(String json) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTVerificationException("json to string error");
        }
    }

    public static ObjectNode stringToJson(String JsonStr) {
        try {
            return (ObjectNode) objectMapper.readTree(JsonStr);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new JWTVerificationException("String to Json Fail!");
        }
    }

    // 将数组转换为字符串
    public static String arrayToString(String[] arrays) {
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
    public static String[] stringToArray(String arrayStr) {
        String[] pairs = arrayStr.split(",");
        String[] arrays = new String[pairs.length];
        for (int i = 0; i < pairs.length; i++) {
            arrays[i] = pairs[i];
        }
        return arrays;
    }

    public static Date getDateByStr(String dateTimeStr) {
        // 创建DateFormat对象
        DateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH);
        try {
            // 解析时间字符串
            Date date = dateFormat.parse(dateTimeStr);

            // 获取秒数
            return date;
        } catch (DateTimeParseException | ParseException | NullPointerException e) {
            throw new JWTVerificationException("DateTime Parse Error or dateTimeStr is null");
        }
    }

    public static long getDateTimeByStr(String dateTimeStr){
        // 创建DateFormat对象
        DateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");
        try {
            // 解析时间字符串
            Date date = dateFormat.parse(dateTimeStr);

            // 获取秒数
            return date.getTime();
        } catch (DateTimeParseException | ParseException | NullPointerException e) {
            throw new JWTVerificationException("DateTime Parse Error or dateTimeStr is null");
        }
    }

    public static Date getDateByTime(String dateTimeStr) {
        // 创建DateFormat对象
        long timeMill = Long.valueOf(dateTimeStr);
        try {
            // 解析时间字符串
            Date date = new Date(timeMill);
            // 获取秒数
            return date;
        } catch (DateTimeParseException | NullPointerException e) {
            throw new JWTVerificationException("DateTime Parse Error or dateTimeStr is null");
        }
    }

    public static Date getDateByTime(Long dateTimeMill) {
        // 创建DateFormat对象
        try {
            // 解析时间字符串
            Date date = new Date(dateTimeMill);
            // 获取秒数
            return date;
        } catch (DateTimeParseException | NullPointerException e) {
            throw new JWTVerificationException("DateTime Parse Error or dateTimeStr is null");
        }
    }
}
