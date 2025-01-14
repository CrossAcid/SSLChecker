package com.crossacid;

import java.io.*;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class Utils {

    public static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    /**
     *
     * @param date 日期
     * @return 返回格式化后的日期
     */
    public static String formatDate(Date date) {
        return sdf.format(date);
    }

    /**
     *
     * @param in 输入流
     * @return 输入流转化的字节数组
     * @description 将 InputStream 转换为字节数组
     */
    public static byte[] inputStreamToArray(InputStream in) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int nRead;
        while (true) {
            try {
                if ((nRead = in.read(data, 0, data.length)) == -1) break;
            } catch (IOException e) {
                System.err.println(e.getMessage());
                throw new RuntimeException(e);
            }
            buffer.write(data, 0, nRead);
        }
        try {
            buffer.flush();
        } catch (IOException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        return buffer.toByteArray();
    }

    /**
     *
     * @return 返回随机数字节数组
     * @description 生成随机数字节数组
     */
    public static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16]; // 生成16字节的nonce值，可以根据需要调整大小
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     *
     * @param sb 待查询字符串
     * @param searchList 查询列表
     * @return 查询列表中是否存在代查询字符串
     * @description 查询列表中是否存在sb
     */
    public static boolean containsAny(StringBuilder sb, List<String> searchList) {
        for (String searchString : searchList) {
            // 使用 indexOf 来检查 StringBuilder 中是否包含该元素
            if (sb.indexOf(searchString) != -1) {
                return true;  // 一旦找到匹配的元素，返回 true
            }
        }
        return false;  // 如果没有任何元素匹配，返回 false
    }
}
