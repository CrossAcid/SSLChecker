package com.crossacid;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException {

        System.setProperty("jdk.tls.disabledAlgorithms", "");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        System.setProperty("jdk.disabled.namedCurves", "");
        Security.setProperty("jdk.security.legacyAlgorithms", "");
        Security.setProperty("crypto.policy", "unlimited");
        System.setProperty("jdk.sunec.disableNative", "false");

        HashSet<String> cipherSuites = new HashSet<String>();
        String domain = "baidu.com";
        boolean stop = false;
        int connectTimeout = 0; // default = infinite
        int readTimeout = 1000;
        boolean showHandshakeErrors = false;
        boolean showSSLErrors = false;
        boolean showErrors = false;
        String errorReportFormat = "%9s %8s %s %s%n";
        String reportFormat = "%9s %8s %s%n";
        boolean hideRejects = false;

//        String[] tlsVersions = {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"};
        List<String> supportProtocols = Arrays.asList("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");
        for (int i = 0; i < supportProtocols.size() && !stop; ++i) {
            String protocol = supportProtocols.get(i);
            String[] supportedCipherSuites = null;
            SecureRandom rand = new SecureRandom();
            try {
                supportedCipherSuites = getJVMSupportedCipherSuites(protocol, rand);
            } catch (NoSuchAlgorithmException nsae) {
                System.out.println(protocol + " Not supported by client");
                supportProtocols.remove(protocol);
            } catch (Exception e) {
                e.printStackTrace();
                // Skip this protocol
            }
//            assert supportedCipherSuites != null;
            cipherSuites.addAll(Arrays.asList(supportedCipherSuites));

            if (cipherSuites.isEmpty()) {
                System.err.println("No overlapping cipher suites found for protocol " + protocol);
                supportProtocols.remove(protocol);
            }
            TrustManagerFactory tmf;
            try {
                tmf = TrustManagerFactory
                        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            // null keystore == default trust store
            try {
                tmf.init((KeyStore) null);
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }

            TrustManager[] trustManagers = tmf.getTrustManagers();


            KeyManagerFactory kmf = null;
            try {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            KeyManager[] keyManagers;
            try {
                kmf.init(null, null);
            } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            ;

            keyManagers = kmf.getKeyManagers();

            for (Iterator<String> j = cipherSuites.iterator(); j.hasNext() && !stop; ) {
                String cipherSuite = j.next();
                String status;
                SSLSocketFactory sf = getSSLSocketFactory(protocol,
                        new String[]{protocol},
                        new String[]{cipherSuite},
                        rand,
                        trustManagers,
                        keyManagers);

                SSLSocket socket = null;
                String error = null;
                InetSocketAddress address = new InetSocketAddress(domain, 443);
                try {
                    socket = createSSLSocket(address, domain, 443, connectTimeout, readTimeout, sf);
                    socket.startHandshake();
                    SSLSession sess = socket.getSession();
                    assert protocol.equals(sess.getProtocol());
                    assert cipherSuite.equals(sess.getCipherSuite());
                    status = "Accepted";
                } catch (SSLHandshakeException she) {
                    Throwable cause = she.getCause();
                    if (null != cause && cause instanceof CertificateException) {
                        status = "Untrusted";
                        error = "Server certificate is not trusted. All other connections will fail similarly.";
                        stop = true;
                    } else
                        status = "Rejected";
                    if (showHandshakeErrors)
                        error = "SHE: " + she.getLocalizedMessage() + ", type=" + she.getClass().getName() + ", nested=" + she.getCause();
                } catch (SSLException ssle) {
                    if (showSSLErrors)
                        error = "SE: " + ssle.getLocalizedMessage();

                    status = "Rejected";
                } catch (SocketTimeoutException ste) {
                    if (showErrors)
                        error = "SocketException" + ste.getLocalizedMessage();

                    status = "Timeout";
                } catch (SocketException se) {
                    if (showErrors)
                        error = se.getLocalizedMessage();

                    status = "Failed";
                } catch (IOException ioe) {
                    if (showErrors)
                        error = ioe.getLocalizedMessage();

                    ioe.printStackTrace();
                    status = "Failed";
                } catch (Exception e) {
                    if (showErrors)
                        error = e.getLocalizedMessage();

                    e.printStackTrace();
                    status = "Failed";
                } finally {
                    if (null != socket) try {
                        socket.close();
                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                    }
                }

                if (null != error)
                    System.out.print(String.format(errorReportFormat,
                            status,
                            protocol,
                            cipherSuite,
                            error));
                else if (!hideRejects || !"Rejected".equals(status))
                    System.out.print(String.format(reportFormat,
                            status,
                            protocol,
                            cipherSuite));


            }
        }

        if (supportProtocols.isEmpty()) {
            System.err.println("This client supports none of the requested protocols: "
                    + List.of(supportProtocols));
            System.err.println("Exiting.");
            System.exit(1);
        }
    }

    private static SSLSocketFactory getSSLSocketFactory(String protocol, String[] sslEnabledProtocols, String[] sslCipherSuites, SecureRandom rand, TrustManager[] trustManagers, KeyManager[] keyManagers) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance(protocol);


        sc.init(keyManagers, trustManagers, rand);

        SSLSocketFactory sf = sc.getSocketFactory();

        if (null != sslEnabledProtocols
                || null != sslCipherSuites)
            sf = new CustomSSLSocketFactory(sf,
                    sslEnabledProtocols,
                    sslCipherSuites);

        return sf;
    }

    public static class CustomSSLSocketFactory
            extends javax.net.ssl.SSLSocketFactory {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLSocketFactory _base;

        public CustomSSLSocketFactory(SSLSocketFactory base,
                                      String[] sslEnabledProtocols,
                                      String[] sslCipherSuites) {
            _base = base;
            if (null == sslEnabledProtocols)
                _sslEnabledProtocols = null;
            else
                _sslEnabledProtocols = sslEnabledProtocols.clone();
            if (null == sslCipherSuites || 0 == sslCipherSuites.length)
                _sslCipherSuites = base.getDefaultCipherSuites();
            else if (1 == sslCipherSuites.length && "ALL".equalsIgnoreCase(sslCipherSuites[0]))
                _sslCipherSuites = base.getSupportedCipherSuites();
            else
                _sslCipherSuites = sslCipherSuites.clone();


        }

        public String[] getDefaultCipherSuites() {
            return _base.getDefaultCipherSuites();
        }

        public String[] getSupportedCipherSuites() {
            return _base.getSupportedCipherSuites();
        }

        private SSLSocket customize(Socket s) {
            SSLSocket socket = (SSLSocket) s;

            if (null != _sslEnabledProtocols)
                socket.setEnabledProtocols(_sslEnabledProtocols);

            socket.setEnabledCipherSuites(_sslCipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(Socket s,
                                   String host,
                                   int port,
                                   boolean autoClose)
                throws IOException {
            return customize(_base.createSocket(s, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port,
                                   InetAddress localHost, int localPort)
                throws IOException {
            return customize(_base.createSocket(host, port, localHost, localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port,
                                   InetAddress localAddress, int localPort)
                throws IOException {
            return customize(_base.createSocket(address, port, localAddress, localPort));
        }
    }

    private static String[] getJVMSupportedCipherSuites(String protocol, SecureRandom rand)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance(protocol);

        sc.init(null, null, rand);

        return sc.getSocketFactory().getSupportedCipherSuites();
    }

    private static SSLSocket createSSLSocket(InetSocketAddress address,
                                             String host,
                                             int port,
                                             int readTimeout,
                                             int connectTimeout,
                                             SSLSocketFactory sf)
            throws IOException {
        //
        // Note: SSLSocketFactory has several create() methods.
        // Those that take arguments all connect immediately
        // and have no options for specifying a connection timeout.
        //
        // So, we have to create a socket and connect it (with a
        // connection timeout), then have the SSLSocketFactory wrap
        // the already-connected socket.
        //
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);

        // Wrap plain socket in an SSL socket
        return (SSLSocket) sf.createSocket(sock, host, port, true);
    }
}
