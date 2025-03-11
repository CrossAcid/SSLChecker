package com.crossacid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author CrossAcid
 * @description
 * @date 2025/3/11
 */
@Slf4j
class CertificateUtilsTest {

    @Test
    void SNICheck() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.SNICheck("expired.badssl.com", 443);
        long endTime = System.currentTimeMillis();
        log.info("SNICheck耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getCommonName() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getCommonName(checkResult.getCertificateChainList()[0], "Subject");
        CertificateUtils.getCommonName(checkResult.getCertificateChainList()[0], "Issuer");
        long endTime = System.currentTimeMillis();
        log.info("getCommonName耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getEncryptionAlgorithm() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getEncryptionAlgorithm(checkResult.getCertificateChainList()[0]);
        long endTime = System.currentTimeMillis();
        log.info("getEncryptionAlgorithm耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getBrand() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getBrand(checkResult.getCertificateChainList()[0]);
        long endTime = System.currentTimeMillis();
        log.info("getBrand耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getType() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getType(checkResult.getCertificateChainList()[0]);
        long endTime = System.currentTimeMillis();
        log.info("getType耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getOrganization() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getOrganization(checkResult.getCertificateChainList()[0]);
        long endTime = System.currentTimeMillis();
        log.info("getOrganization耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getOrganizationalUnit() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        CertificateUtils.getOrganizationalUnit(checkResult.getCertificateChainList()[0]);
        long endTime = System.currentTimeMillis();
        log.info("getOrganizationalUnit耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getSubjectAlternativeName() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        try {
            CertificateUtils.getSubjectAlternativeName(checkResult.getCertificateChainList()[0]);
        } catch (CertificateParsingException e) {
            log.error("getSubjectAlternativeName异常", e);
        }
        long endTime = System.currentTimeMillis();
        log.info("getSubjectAlternativeName耗时：" + (endTime - startTime) + "ms");
    }

    @Test
    void getRevokedStatus() {
        CheckResult checkResult = CertificateUtils.SNICheck("baidu.com", 443);
        long startTime = System.currentTimeMillis();
        try {
            CertificateUtils.getRevokedStatus((X509Certificate) checkResult.getCertificateChainList()[0], (X509Certificate) checkResult.getCertificateChainList()[1]);
        } catch (Exception e) {
            log.error("getRevokedStatus异常", e);
        }
        long endTime = System.currentTimeMillis();
        log.info("getRevokedStatus耗时：" + (endTime - startTime) + "ms");
    }

}