package com.crossacid;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.cert.Certificate;
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

    static Certificate[] certificates;

    static {
        certificates = CertificateUtils.SNICheck("baidu.com", 443).getCertificateChainList();
    }

    @Test
    void SNICheck() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.SNICheck("expired.badssl.com", 443);
        long endTime = System.currentTimeMillis();
        log.info("SNICheck耗时：{}ms", endTime - startTime);
    }

    @Test
    void getCommonName() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getCommonName(certificates[0], "Subject");
        CertificateUtils.getCommonName(certificates[0], "Issuer");
        long endTime = System.currentTimeMillis();
        log.info("getCommonName耗时：{}ms", endTime - startTime);
    }

    @Test
    void getEncryptionAlgorithm() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getEncryptionAlgorithm(certificates[0]);
        long endTime = System.currentTimeMillis();
        log.info("getEncryptionAlgorithm耗时：{}ms", endTime - startTime);
    }

    @Test
    void getBrand() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getBrand(certificates[0]);
        long endTime = System.currentTimeMillis();
        log.info("getBrand耗时：{}ms", endTime - startTime);
    }

    @Test
    void getType() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getType(certificates[0]);
        long endTime = System.currentTimeMillis();
        log.info("getType耗时：{}ms", endTime - startTime);
    }

    @Test
    void getOrganization() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getOrganization(certificates[0]);
        long endTime = System.currentTimeMillis();
        log.info("getOrganization耗时：{}ms", endTime - startTime);
    }

    @Test
    void getOrganizationalUnit() {
        long startTime = System.currentTimeMillis();
        CertificateUtils.getOrganizationalUnit(certificates[0]);
        long endTime = System.currentTimeMillis();
        log.info("getOrganizationalUnit耗时：{}ms", endTime - startTime);
    }

    @Test
    void getSubjectAlternativeName() {
        long startTime = System.currentTimeMillis();
        try {
            CertificateUtils.getSubjectAlternativeName(certificates[0]);
        } catch (CertificateParsingException e) {
            log.error("getSubjectAlternativeName异常", e);
        }
        long endTime = System.currentTimeMillis();
        log.info("getSubjectAlternativeName耗时：{}ms", endTime - startTime);
    }

    @Test
    void getRevokedStatus() {
        long startTime = System.currentTimeMillis();
        try {
            CertificateUtils.getRevokedStatus((X509Certificate) certificates[0], (X509Certificate) certificates[1]);
        } catch (Exception e) {
            log.error("getRevokedStatus异常", e);
        }
        long endTime = System.currentTimeMillis();
        log.info("getRevokedStatus耗时：{}ms", endTime - startTime);
    }

}