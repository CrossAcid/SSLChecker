package com.crossacid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Date;
import java.util.List;


/**
 * @author CrossAcid
 * @description
 * @date 2025/3/11
 */
@Slf4j
class UtilsTest {

    @Test
    void formatDate() {
        Date date = new Date();
        long start = System.currentTimeMillis();
        Utils.formatDate(date);
        long end = System.currentTimeMillis();
        log.info("formatDate耗时: {}ms", end - start);
    }

    @Test
    void inputStreamToArray() {
        InputStream in = getClass().getResourceAsStream("/log4j.properties");
        long start = System.currentTimeMillis();
        assert in != null;
        Utils.inputStreamToArray(in);
        long end = System.currentTimeMillis();
        log.info("inputStreamToArray耗时: {}ms", end - start);
    }

    @Test
    void generateNonce() {
        long start = System.currentTimeMillis();
        Utils.generateNonce();
        long end = System.currentTimeMillis();
        log.info("generateNonce耗时: {}ms", end - start);
    }

    @Test
    void containsAny() {
        long start = System.currentTimeMillis();
        Utils.containsAny(new StringBuilder("abc"), List.of("abc", "b"));
        long end = System.currentTimeMillis();
        log.info("containsAny耗时: {}ms", end - start);
    }
}