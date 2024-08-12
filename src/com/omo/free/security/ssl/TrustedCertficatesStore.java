/**
 *
 */
package com.omo.free.security.ssl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This class is used for creating a Trusted Certificates Keystore and place a copy of a secure websites certificate within it.
 *
 * @author Richard Salas
 */
public class TrustedCertficatesStore {

    private static final String MY_CLASS_NAME = "com.omo.free.security.ssl.TrustedCertficatesStore";
    private static Logger myLogger = Logger.getLogger(MY_CLASS_NAME);

    private static final String TRUST_STORE_PROPERTY_NM = "javax.net.ssl.trustStore";
    private static final String TRUST_STORE_NM = "cacerts";

    private String httpsURL;
    private Path truststoreFile;

    /**
     * Constructor used to create an instance of the TrustedCertficatesStore. An exception will be thrown if the key store is unable to be created.
     *
     * @param trustStoreDirPath
     *        the parent directory where the certificate truststore should be created.
     * @param httpsURL
     *        the url of the website to establish a secure handshake (Ex: https://servernamea.isu.net)
     * @throws Exception
     *         if keystore is unable to be created
     */
    public TrustedCertficatesStore(String trustStoreDirPath, String httpsURL) throws Exception {
        myLogger.entering(MY_CLASS_NAME, "TrustedCertficatesStore", new Object[]{trustStoreDirPath, httpsURL});

        // added this logic to attempt to create auto create local directory
        Files.createDirectories(Paths.get(trustStoreDirPath));

        if(!Files.exists(Paths.get(trustStoreDirPath))){
            throw new IllegalArgumentException("The directory path " + String.valueOf(trustStoreDirPath) + " does not exist!  An attempt was also made to create this directory structure but failed.  It must be created before creating an instance of the TrustedCertficatesStore");
        }// end if

        if(httpsURL == null || !httpsURL.startsWith("https://") || httpsURL.endsWith("/")){
            throw new IllegalArgumentException("The url is incorrectly formatted: " + String.valueOf(httpsURL) + ".  Please send a correctly formatted URL ie. https://www.abc.com ");
        }// end if

        this.truststoreFile = Paths.get(trustStoreDirPath, "cacerts");
        this.httpsURL = httpsURL;

        if(!Files.exists(this.truststoreFile)){
            // create the local truststore
            createLocalTrustStore();
        }// end if

        // check web server certficate and set the truststore location property
        checkWebServerCertificate();
        setTrustStoreLocationProperty();

        myLogger.exiting(MY_CLASS_NAME, "TrustedCertficatesStore", trustStoreDirPath);
    }// end constructor

    /**
     * This method will create a local truststore. This method will copy the currently running java Runtime's cacerts file to local destination.
     */
    private void createLocalTrustStore() {
        myLogger.entering(MY_CLASS_NAME, "createLocalTrustStore");

        /* below logic is used for getting the default truststore cacerts from users java installation directory */
        Path caCertsPath = Paths.get(System.getProperty("java.home"), "lib", "security", TRUST_STORE_NM);

        FileInputStream is = null;
        FileOutputStream fos = null;
        KeyStore keystore = null;
        char[] password = null;

        try{
            myLogger.info("loading cacerts file from: " + String.valueOf(caCertsPath.toString()));
            is = new FileInputStream(caCertsPath.toFile());
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            password = "changeit".toCharArray();// this is the default password
            keystore.load(is, password);

            // create file
            Path truststoreFile = Paths.get(this.truststoreFile.getParent().toString(), TRUST_STORE_NM);
            Files.createFile(truststoreFile);

            // copy installations truststore file into local truststore file
            fos = new FileOutputStream(truststoreFile.toFile());
            keystore.store(fos, password);
        }catch(NoSuchAlgorithmException e){
            myLogger.log(Level.SEVERE, "NoSuchAlgorithmException occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }catch(FileNotFoundException e){
            myLogger.log(Level.SEVERE, "FileNotFoundException occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }catch(KeyStoreException e){
            myLogger.log(Level.SEVERE, "KeyStoreException occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }catch(CertificateException e){
            myLogger.log(Level.SEVERE, "CertificateException occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }catch(IOException e){
            myLogger.log(Level.SEVERE, "IOException occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }catch(Exception e){
            myLogger.log(Level.SEVERE, "Exception occurred during the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
        }finally{
            try{
                if(is != null){
                    is.close();
                }// end if
            }catch(IOException e){
                myLogger.log(Level.SEVERE, "IOException occurred while trying to close the inputstream used in the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
            }// end try...catch

            try{
                if(fos != null){
                    fos.close();
                }// end if
            }catch(IOException e){
                myLogger.log(Level.SEVERE, "IOException occurred while trying to close the outputstream used in the createLocalTrustStore process.  Error message is: " + e.getMessage(), e);
            }// end try...catch
        }// end try...catch...finally
        myLogger.exiting(MY_CLASS_NAME, "createLocalTrustStore");
    }// end createLocalTrustStore

    /**
     * This method will make sure that the web certificate is trusted, if it is not then an attempt to store the certificate in the keystore is made.
     *
     * @param url
     *        the url used to check for certificate
     */
    public void checkWebServerCertifcate(String url) {
        myLogger.entering(MY_CLASS_NAME, "checkWebServerCertifcate", url);
        this.httpsURL = url;
        checkWebServerCertificate();
        myLogger.exiting(MY_CLASS_NAME, "checkWebServerCertifcate");
    }// end checkWebServerCertifcate

    /**
     * This method will check to see if the web certificate is trusted already.
     */
    private void checkWebServerCertificate() {
        myLogger.entering(MY_CLASS_NAME, "checkWebServerCertificate");

        // splitting the host name for gathering parameters used to establish a handshake with server.
        String[] hostArray = this.httpsURL.replace("https://", "").split(":");
        String host = hostArray[0];
        int port = (hostArray.length == 1) ? 443 : Integer.parseInt(hostArray[1]);
        char[] passphrase = "changeit".toCharArray(); // default password

        InputStream in = null;
        KeyStore ks = null;
        SSLContext context = null;
        TrustManagerFactory tmf = null;
        X509TrustManager defaultTrustManager = null;
        SavingTrustManager tm = null;

        SSLSocketFactory factory = null;
        SSLSocket socket = null;

        OutputStream out = null;
        try{
            myLogger.info("Starting to load the cacerts file: " + this.truststoreFile.toString());
            // obtain the file path and then load the KeyStore
            in = new FileInputStream(this.truststoreFile.toFile());
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, passphrase);// load
            in.close();

            // get TLS context
            context = SSLContext.getInstance("TLS");
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[]{tm}, null);
            factory = context.getSocketFactory();

            myLogger.info("Attempting to open a connection to " + String.valueOf(host) + ":" + String.valueOf(port));
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(10000);
            boolean isHandshakeError = false;
            try{
                myLogger.info("Initiating the handshake with server.");
                socket.startHandshake();
                socket.close();
            }catch(SSLException e){
                if("java.lang.UnsupportedOperationException".equals(e.getMessage())){
                    myLogger.info("certificate is already trusted");
                }else if(e.getMessage().contains("unable to find valid certification path to requested target")){
                    myLogger.info("Client did not accept the server's handshake for host " + String.valueOf(host) + ".  It will be accepted and injected into local truststore.");
                    isHandshakeError = true;
                }else if(e.getMessage().contains("expired") || e.getMessage().contains("SSLHandshakeException")){
                    if(Files.exists(this.truststoreFile)){
                        Files.delete(this.truststoreFile);
                        // create the local truststore
                        createLocalTrustStore();
                        isHandshakeError = true;
                    }// end if
                }// end if
            }// end try...catch

            if(isHandshakeError){
                X509Certificate[] chain = tm.chain;
                if(chain == null){
                    myLogger.info("Could not obtain the servers certificate chain");
                    return;
                }// end if

                myLogger.info("Server sent " + chain.length + " certificate(s):");

                X509Certificate certificate = null;
                certificate = chain[chain.length - 1];
                if(certificate != null){
                    String alias = host + "-ISU";
                    ks.setCertificateEntry(alias, certificate);

                    out = new FileOutputStream(this.truststoreFile.toFile());
                    ks.store(out, passphrase);
                    out.close();
                    myLogger.info("Successfully saved new " + alias + " certificate to " + this.truststoreFile.toString());
                }// end if
            }else{
                myLogger.info("Host certificate " + String.valueOf(host) + " is already trusted.");
            }// end if
        }catch(NoSuchAlgorithmException e){
            myLogger.log(Level.SEVERE, "NoSuchAlgorithmException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(FileNotFoundException e){
            myLogger.log(Level.SEVERE, "FileNotFoundException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(KeyStoreException e){
            myLogger.log(Level.SEVERE, "KeyStoreException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(CertificateException e){
            myLogger.log(Level.SEVERE, "CertificateException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(IOException e){
            myLogger.log(Level.SEVERE, "IOException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(KeyManagementException e){
            myLogger.log(Level.SEVERE, "KeyManagementException occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }catch(Exception e){
            myLogger.log(Level.SEVERE, "Exception occurred during the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
        }finally{
            // close all resources
            try{
                if(out != null){
                    out.close();
                }// end if
            }catch(IOException e){
                myLogger.log(Level.SEVERE, "IOException occurred while trying to close the outputstream used in the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
            }// end try...catch

            try{
                if(in != null){
                    in.close();
                }// end if
            }catch(IOException e){
                myLogger.log(Level.SEVERE, "IOException occurred while trying to close the inputstream used in the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
            }// end try...catch

            try{
                if(socket != null){
                    socket.close();
                }// end if
            }catch(IOException e){
                myLogger.log(Level.SEVERE, "IOException occurred while trying to close the socket used in the checkWebServerCertificate process.  Error message is: " + e.getMessage(), e);
            }// end try...catch
        }// end try...catch...finally
        myLogger.exiting(MY_CLASS_NAME, "checkWebServerCertificate");
    }// end checkWebServerCertificate

    /**
     * This method will set the javax.net.ssl.trustStore property. The only requirement is that it needs to exist.
     */
    public void setTrustStoreLocationProperty() {
        myLogger.entering(MY_CLASS_NAME, "setTrustStoreLocationProperty");

        try{
            System.setProperty(TRUST_STORE_PROPERTY_NM, this.truststoreFile.toFile().getCanonicalPath());
        }catch(Exception e){
            throw new RuntimeException("Problem trying to set truststore location using the getCanonicalPath() method.  Error message is: " + e.getMessage());
        }// end try...catch

        myLogger.exiting(MY_CLASS_NAME, "setTrustStoreLocationProperty");
    }// end setTrustStoreLocationProperty

    /**
     * This class is used for checking the servers trusted certificates.
     * <p>
     * The primary responsibility of the TrustManager is to determine whether the presented authentication credentials should be trusted. If the credentials are not trusted, then the connection will be terminated.
     * </p>
     */
    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        /**
         * @param tm
         */
        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }// end constructor

        /**
         * {@inheritDoc}
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }// end getAcceptedIssuers

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }// end checkClientTrusted

        /**
         * {@inheritDoc}
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }// end checkServerTrusted

    }// end class

}// end class
