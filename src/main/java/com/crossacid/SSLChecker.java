package com.crossacid;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;


public class SSLChecker {

    protected static String TAB = "  ";
    protected StringBuilder supportSSLProtocolsDesc = new StringBuilder();
    public StringBuilder certChainInfo = new StringBuilder();
    public boolean supportSNIDesc;

    public SSLChecker() {}

    public String run(String domain, boolean suggestions) {
        StringBuilder result = new StringBuilder();
        // 0. 检测支持的SSL协议
        List<String> protocolsToTest = Arrays.asList("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");
        for (String protocol : protocolsToTest) {
            checkProtocolSupport(domain, protocol);
        }

        // 1. 证书预定义
        Certificate[] certificates = new Certificate[0];

        // 1.1 获取证书信息
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        // 是否支持SNI

        try {
            SSLSocket socket = (SSLSocket) factory.createSocket(domain, 443);

            // 尝试SNI连接
            try {
                SSLParameters sslParameters = socket.getSSLParameters();
                sslParameters.setServerNames(Collections.singletonList(new SNIHostName(domain)));
                socket.setSSLParameters(sslParameters);

                socket.startHandshake();
                SSLSession sslSession = socket.getSession();

                certificates = sslSession.getPeerCertificates();
                supportSNIDesc = true;
            } catch (SSLHandshakeException e) {
                System.err.println("SNI handshake failed, retrying without SNI: {}" + e.getMessage());
                supportSNIDesc = false;

                socket = (SSLSocket) factory.createSocket(domain, 443);

                // 发起不带 SNI 的握手
                socket.startHandshake();
                SSLSession sslSession = socket.getSession();

                certificates = sslSession.getPeerCertificates(); // 获取证书
            } finally {
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("IOException: {}" + e.getMessage());
        }

        if (certificates.length == 0) {
            System.err.println("No certificate found");
            return null;
        }

        // 2. 证书链信息
        try {
            checkCertChainInfo(certificates);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // 3. 协议与套件


        //   3.1 支持协议


        //   3.2 支持的加密套件


        // 4. 总结


        // 5. 建议


        return generateResult(domain, result);
    }

    private void checkCertChainInfo(Certificate[] certificates) throws NoSuchAlgorithmException {
        System.out.println(certificates.length);
        for (int i = 0; i < certificates.length; i++) {
            if (certificates[i] instanceof X509Certificate cert) {
                this.certChainInfo.append("Certificate ").append(i + 1).append(": ").append("\n");
                generateCertChainInfo(cert);
            }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try {
            tmf.init((KeyStore) null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x509TrustManager) {
                X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
                for (X509Certificate rootCert : acceptedIssuers) {
                    // 检查根证书是否匹配最后一个中间证书的颁发者并输出根证书
                    if (rootCert.getSubjectX500Principal().equals(((X509Certificate)certificates[certificates.length - 1]).getIssuerX500Principal())) {
                        this.certChainInfo.append("Certificate ").append(certificates.length + 1).append(": ").append("\n");
                        generateCertChainInfo(rootCert);
                    }
                }
            }
        }
    }

    private void generateCertChainInfo(X509Certificate certificate) {
        this.certChainInfo.append("颁发给: ").append(certificate.getSubjectX500Principal()).append("\n");
        this.certChainInfo.append("颁发者: ").append(certificate.getIssuerX500Principal()).append("\n");
        this.certChainInfo.append("有效期: ")
                .append(CertificateUtils.formatDate(certificate.getNotBefore()))
                .append(" ~ ")
                .append(CertificateUtils.formatDate(certificate.getNotAfter()))
                .append(" 剩余 ")
                .append(TimeUnit.DAYS.convert(Math.abs(certificate.getNotAfter().getTime() - new Date().getTime()), TimeUnit.MILLISECONDS))
                .append(" 天 ")
                .append("\n");
    }


    private void checkProtocolSupport(String domain, String protocol) {
        try {
            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket;
            sslSocket = (SSLSocket) sslSocketFactory.createSocket(domain, 443);
            sslSocket.setEnabledProtocols(new String[]{protocol});

            sslSocket.startHandshake();

            this.supportSSLProtocolsDesc.append(TAB).append(TAB).append(protocol).append(" support").append("\n");
        } catch (UnknownHostException e) {
            System.err.println("Unknown host: " + domain);
        } catch (IOException e) {
            this.supportSSLProtocolsDesc.append(TAB).append(TAB).append(protocol).append(" not support").append("\n");
        }
    }

    public String generateResult(String domain, StringBuilder result) {

        result.append("检测域名: ").append(domain).append("\n");

        // 1.证书信息
        result.append("证书信息").append("\n");
        result.append("通用名称: ").append("").append("\n");
        result.append("颁发者: ").append("").append("\n");
        result.append("启用SNI: ").append(supportSNIDesc).append("\n");
        result.append("弱密钥检测: ").append("").append("\n");
        result.append("加密算法: ").append("").append("\n");
        result.append("签名算法: ").append("").append("\n");
        result.append("证书品牌: ").append("").append("\n");
        result.append("证书类型: ").append("").append("\n");
        result.append("开始时间: ").append("").append("\n");
        result.append("结束时间: ").append("").append("\n");
        result.append("吊销状态: ").append("").append("\n");
        result.append("组织机构: ").append("").append("\n");
        result.append("部门: ").append("").append("\n");
        result.append("备用名称: ").append("").append("\n");
        result.append("\n");

        // 2.证书链信息
        result.append("证书链信息: ").append("\n");
        result.append(certChainInfo).append("\n");

        // 3.协议与套件
        result.append("协议与套件:").append("\n");
        // 3.1 支持协议
        result.append(TAB).append("支持协议:").append("\n");
        result.append(supportSSLProtocolsDesc).append("\n");
        // 3.2 支持套件
        result.append(TAB).append("支持的加密套件:").append("\n");
        result.append("\n");

        // 4.总结
        result.append("总结:").append("\n");
        result.append(TAB).append("是否符合ATS:").append("\n");
        result.append(TAB).append("是否符合PCI DSS:").append("\n");
        result.append(TAB).append("评级:").append("\n");
        result.append("\n");

        // 5.建议
        result.append("建议:").append("\n");
        System.out.println(result);
        return result.toString();

    }

}
