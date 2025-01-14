package com.crossacid;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.crypto.interfaces.DHPublicKey;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CertificateUtils {



    /**
     *
     * @param certificate 证书
     * @param type 颁发者or被颁发者
     * @return 获得通用名称
     */
    public static String getCommonName(Certificate certificate, String type) {
        String cnPattern = "CN=([^,]+)";
        Pattern pattern = Pattern.compile(cnPattern);
        if (certificate instanceof X509Certificate x509Cert) {
            Matcher matcher;
            if (type.equals("Subject")) {
                matcher = pattern.matcher(x509Cert.getSubjectX500Principal().getName());
            } else if (type.equals("Issuer")) {
                matcher = pattern.matcher(x509Cert.getIssuerX500Principal().getName());
            } else {
                return null;
            }
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    /**
     *
     * @param certificate 证书
     * @return 获取加密算法信息
     */
    public static String getEncryptionAlgorithm(Certificate certificate) {
        return certificate.getPublicKey().getAlgorithm() + " " + getPublicKeyAlgorithmSize(certificate);
    }

    /**
     *
     * @param certificate 证书
     * @return 获取公钥算法
     */
    private static String getPublicKeyAlgorithmSize(Certificate certificate) {
        PublicKey publicKey = certificate.getPublicKey();
        int keySize = 0;
        if (publicKey instanceof RSAPublicKey) {
            keySize = ((RSAPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof ECPublicKey) {
            keySize = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
        } else if (publicKey instanceof DSAPublicKey) {
            keySize = ((DSAPublicKey) publicKey).getY().bitLength();
        } else if (publicKey instanceof DHPublicKey) {
            keySize = ((DHPublicKey) publicKey).getY().bitLength();
        }
        return keySize + " bits";
    }

    /**
     *
     * @param certificate 证书
     * @return 返回证书品牌
     */
    public static String getBrand(Certificate certificate) {
        String issuer = ((X509Certificate) certificate).getIssuerX500Principal().getName();
        String brand = issuer.replaceAll(".*CN=([^,]+).*", "$1");
        if (brand.contains("GlobalSign")) {
            return "GlobalSign";
        } else if (brand.contains("DigiCert")) {
            return "DigiCert";
        } else if (brand.contains("Sectigo")) {
            return "Sectigo";
        } else if (brand.contains("Certum")) {
            return "Certum";
        } else if (brand.contains("GeoTrust")) {
            return "GeoTrust";
        } else {
            return "其他品牌";
        }
    }

    /**
     *
     * @param certificate 证书
     * @return 获取证书类型
     */
    public static String getType(Certificate certificate) {
        String subjectString = ((X509Certificate) certificate).getSubjectX500Principal().toString();
        // 检测Subject判断是否为DV
        if (!subjectString.contains("O=")) {
            return "DV SSL";
        } else {
            // 检查证书Subject以确定是否为 EV
            if (!subjectString.contains("SERIALNUMBER=")) {
                return "OV SSL";
            }
            return "EV SSL";
        }
    }

    /**
     *
     * @param certificate 证书
     * @return 返回证书机构
     */
    public static String getOrganization(Certificate certificate) {
        String organization = ""; // 去除首尾空格

        try {
            String subject = String.valueOf(((X509Certificate) certificate).getSubjectX500Principal());
            String regex = "O=\"([^\"]*)\"|O=([^,]*)";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(subject);

            while (matcher.find()) {
                // 输出 O= 后面的内容
                if (matcher.group(1) != null) {
                    organization = matcher.group(1);
                } else if (matcher.group(2) != null) {
                    organization = matcher.group(2);
                }
                if (organization != null) {
                    organization = organization.trim();
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return Objects.equals(organization, "") ? "-" : organization;
    }

    /**
     *
     * @param certificate 证书
     * @return 返回证书OU
     */
    public static String getOrganizationalUnit(Certificate certificate) {
        String subject = String.valueOf(((X509Certificate) certificate).getSubjectX500Principal());
        String department = subject.replaceAll(".*OU=([^,]+).*", "$1");
        if (department.equals(subject)) {
            return "-";
        }
        return department;
    }

    /**
     *
     * @param certificate 证书
     * @return 获取证书备用名称
     * @throws CertificateParsingException 防止证书转化错误
     */
    public static List<String> getSubjectAlternativeName(Certificate certificate) throws CertificateParsingException {
        List<String> sanList = new ArrayList<>();
        Collection<List<?>> sanEntries = ((X509Certificate) certificate).getSubjectAlternativeNames();
        if (sanEntries != null) {
            for (List<?> sanItem : sanEntries) {
                String san = (String) sanItem.get(1);  // 备用名称内容
                sanList.add(san);
            }
        }
        return sanList;
    }

    /**
     * @param certificate     证书
     * @param issuerCertificate 颁发证书者
     * @return 证书吊销状态
     * @description 根据OCSP验证证书是否吊销
     */
    public static String getRevokedStatus(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {

        // 1.获取证书OCSP验证地址
        byte[] aiaExtensionValue = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
        List<String> ocspUrls = new ArrayList<>();
        if (aiaExtensionValue != null) {
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue));
            ASN1Primitive derObject = asn1InputStream.readObject();
            byte[] octets = ((ASN1OctetString) derObject).getOctets();
            ASN1InputStream aiaStream = new ASN1InputStream(new ByteArrayInputStream(octets));
            ASN1Sequence aiaSequence = (ASN1Sequence) aiaStream.readObject();
            AuthorityInformationAccess authorityInfoAccess = AuthorityInformationAccess.getInstance(aiaSequence);

            AccessDescription[] descriptions = authorityInfoAccess.getAccessDescriptions();
            for (AccessDescription description : descriptions) {
                if (description.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName name = description.getAccessLocation();
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String ocspUrl = name.getName().toString();
                        ocspUrls.add(ocspUrl);
                    }
                }
            }
        }

        // 2.ocspUrl即验证的地址
        String ocspUrl = ocspUrls.get(0);

        OCSPResp ocspResponse;
        try {
            ocspResponse = CertificateUtils.getOcspResponse(certificate, issuerCertificate, ocspUrl);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return "Check failed";
        }
        if (ocspResponse == null) {
            System.err.println("Can't get OCSPResponse");
            return "Check failed";
        }
        if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {  //判断此次连接返回的响应结果
            System.err.println("Failed to get OCSPResponse");
            return "Check failed";
        }
        BasicOCSPResp basicResponse;  //获取到BasicOCSPResp
        try {
            basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return "Check failed";
        }

        if (basicResponse != null) {
            SingleResp[] responses = basicResponse.getResponses();
            if (responses.length == 1) {
                SingleResp resp = responses[0];
                Object status = resp.getCertStatus();
                if (status == CertificateStatus.GOOD) {
                    return "正常";
                } else if (status instanceof RevokedStatus) {
                    return "证书吊销";
                } else {
                    System.err.println("ocsp校验结果:" + "ocsp.status.is.unknown");
                    return "Check failed";
                }
            }
        }
        return "Check failed";
    }

    /**
     *
     * @param certificate 待获取OCSP响应的证书
     * @param issuerCertificate 颁发待检测证书的证书
     * @param ocspUrl OCSP请求URL
     * @return OCSP响应
     */
    public static OCSPResp getOcspResponse(X509Certificate certificate, X509Certificate issuerCertificate, String ocspUrl) throws IOException {
        if (certificate == null || issuerCertificate == null) {
            return null;
        }
        if (ocspUrl == null) {
            return null;
        }
        OCSPReq request = generateOCSPRequest(issuerCertificate, certificate.getSerialNumber());
        byte[] array = request.getEncoded();
        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.setDoOutput(true);
        con.setConnectTimeout(3000);
        con.setReadTimeout(5000);
        OutputStream out = con.getOutputStream();
        DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
        dataOut.write(array);
        dataOut.flush();
        dataOut.close();
        if (con.getResponseCode() / 100 != 2) {
            System.err.println("Bad ResponseCode");
        }
        // Get Response
        InputStream in = (InputStream) con.getContent();
        return new OCSPResp(Utils.inputStreamToArray(in));
    }

    /**
     *
     * @param issuerCertificate 颁发者证书
     * @param serialNumber 序列号
     * @return OCSPReq
     */
    private static OCSPReq generateOCSPRequest(X509Certificate issuerCertificate, BigInteger serialNumber) {
        Security.addProvider(new BouncyCastleProvider());
        CertificateID id;
        try {
            id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCertificate), serialNumber);
        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(id);
        byte[] nonceValue = Utils.generateNonce();
        Extension extension;
        try {
            extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(new DEROctetString(nonceValue)));
        } catch (IOException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        ocspReqBuilder.setRequestExtensions(new Extensions(new Extension[] { extension }));
        try {
            return ocspReqBuilder.build();
        } catch (OCSPException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
