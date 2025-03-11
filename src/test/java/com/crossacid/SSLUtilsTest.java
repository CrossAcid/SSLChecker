package com.crossacid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author CrossAcid
 * @description
 * @date 2025/3/11
 */
@Slf4j
class SSLUtilsTest {

    @Test
    void getCustomSSLSocket() throws IOException {
        InetSocketAddress address = new InetSocketAddress("baidu.com", 443);
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        long start = System.currentTimeMillis();
        SSLUtils.getCustomSSLSocket(address, 0, 1000, sslSocketFactory);
        long end = System.currentTimeMillis();
        log.info("getCustomSSLSocket cost: {}ms", end - start);
    }

    @Test
    void getCertificatesWithoutValidation() {
        long start = System.currentTimeMillis();
        SSLUtils.getCertificatesWithoutValidation("baidu.com", 443);
        long end = System.currentTimeMillis();
        log.info("getCertificatesWithoutValidation cost: {}ms", end - start);
    }

    @Test
    void getCustomSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        String protocol = "TLSv1.2";
        String cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        SecureRandom rand = new SecureRandom();
        long start = System.currentTimeMillis();
        SSLUtils.getCustomSSLSocketFactory(protocol, new String[]{protocol}, new String[]{cipherSuite}, rand, null, null);
        long end = System.currentTimeMillis();
        log.info("getSSLSocketFactory cost: {}ms", end - start);
    }

    @Test
    void getDefaultTrustManagers() {
        long start = System.currentTimeMillis();
        SSLUtils.getDefaultTrustManagers();
        long end = System.currentTimeMillis();
        log.info("getDefaultTrustManagers cost: {}ms", end - start);
    }

    @Test
    void getCustomTrustManagers() {
        long start = System.currentTimeMillis();
        SSLUtils.getCustomTrustManagers();
        long end = System.currentTimeMillis();
        log.info("getCustomTrustManagers cost: {}ms", end - start);
    }

    @Test
    void getKeyManagers() {
        long start = System.currentTimeMillis();
        SSLUtils.getKeyManagers();
        long end = System.currentTimeMillis();
        log.info("getKeyManagers cost: {}ms", end - start);
    }
}