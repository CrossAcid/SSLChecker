package com.crossacid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author CrossAcid
 * @description
 * @date 2025/3/11
 */
@Slf4j
class CipherSuiteUtilsTest {

    @Test
    void getJVMSupportedCipherSuites() throws NoSuchAlgorithmException, KeyManagementException {
        String protocol = "TLSv1.2";
        SecureRandom rand = new SecureRandom();
        long start = System.currentTimeMillis();
        CipherSuiteUtils.getJVMSupportedCipherSuites(protocol, rand);
        long end = System.currentTimeMillis();
        log.info("getJVMSupportedCipherSuites cost: {}ms", end - start);
    }


    @Test
    void getCipherSuitScore() {
        String protocol = "TLSv1.2";
        String cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        long start = System.currentTimeMillis();
        CipherSuiteUtils.getCipherSuitScore(protocol, cipherSuite);
        long end = System.currentTimeMillis();
        log.info("getCipherSuitScore cost: {}ms", end - start);
    }
}