package kz.ets;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.util.encoders.Base64;
import kz.gov.pki.provider.exception.ProviderUtilException;
import kz.gov.pki.provider.utils.CMSUtil;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.sql.Timestamp;
import java.sql.*;
import java.util.Date;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecureManager {

    private static PropsManager props = PropsManager.getInstance();
    private static Logger logger = LogManager.getLogger(SecureManager.class);

    //final static Logger log = Logger.getLogger(SecureManager.class.getName());
    final static Map<String, TypeOfCrlLoaded> MAP_OF_LOAD_CRL_LABEL; //
    final static Map MAP_OF_XCRL;
    final static Map<String, Date> MAP_OF_LOAD_CRL_TIME;
    final static Map<String, String> MAP_OF_CRL_PATH;
    final static Integer HOURS_OF_RELOAD = 3;

    // Всего в данном примере используется четыре  возможных варианта
    // загрузки CRL-файлов это два типа сертификатов (RSA и GOST) для двух типов систем (НУЦ_1 и НУЦ_2)
    final static String CRL_GOST_1 = "CRL_GOST_1";
    final static String CRL_GOST_2 = "CRL_GOST_2";
    final static String CRL_RSA_1 = "CRL_RSA_1";
    final static String CRL_RSA_2 = "CRL_RSA_2";
    final static String NO_OBJECT = "NO_OBJECT";

    final static String DEFAUL_CERT_NUC1_GOST = props.getProperty("DEFAUL_CERT_NUC1_GOST_PATH");
    final static String DEFAUL_CERT_NUC1_RSA = props.getProperty("DEFAUL_CERT_NUC1_RSA");
    final static String DEFAUL_CERT_NUC2_GOST = props.getProperty("DEFAUL_CERT_NUC2_GOST");
    final static String DEFAUL_CERT_NUC2_RSA = props.getProperty("DEFAUL_CERT_NUC2_RSA_PATH");
    final static String DEFAUL_CERT_KUC_GOST = props.getProperty("DEFAUL_CERT_KUC_GOST_PATH");
    final static String DEFAUL_CERT_KUC_RSA = props.getProperty("DEFAUL_CERT_KUC_RSA_PATH");
    //static final String NO_ERROR = "NO_ERROR";
    final static Boolean DEFAUL_USE_PROXY = false;
    //final static String DEFAUL_PROXY_ADDRESS="172.25.43.2";
    final static String DEFAUL_PROXY_ADDRESS = props.getProperty("PROXY.HOST");
    //final static Integer DEFAUL_PROXY_PORT = 3128;
    final static Integer DEFAUL_PROXY_PORT = Integer.valueOf(props.getProperty("PROXY.PORT"));
    static AtomicBoolean canWorkWithKalkan = new AtomicBoolean(false);
    static String kalkanErrorMessage = "";
    static String providerName = "No_Name";

    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    //private static final String url = "jdbc:mysql://10.160.235.20:3306/db_kc?useUnicode=true&characterEncoding=UTF-8";
    private static final String url = "jdbc:mysql://" + props.getProperty("MYSQL.HOST") + "/db_kc?useUnicode=true&characterEncoding=UTF-8&useSSL=false";
    private static final String user = props.getProperty("MYSQL.USER");
    private static final String password = props.getProperty("MYSQL.PWD");

    public String certinfo = null;
    public String BrokerCode = null;

    String respName;
    String realBinIin;
    TypeOfRespondent typeOfRespondent;
    String verifyErrorMsg = "";

    String pathCertNuc1Gost = DEFAUL_CERT_NUC1_GOST;
    String pathCertNuc1Rca = DEFAUL_CERT_NUC1_RSA;
    String pathCertNuc2Gost = DEFAUL_CERT_NUC2_GOST;
    String pathCertNuc2Rca = DEFAUL_CERT_NUC2_RSA;
    String pathCertKucGost = DEFAUL_CERT_KUC_GOST;
    String pathCertKucRca = DEFAUL_CERT_KUC_RSA;

    Boolean useProxy = DEFAUL_USE_PROXY;
    String proxyAddress = DEFAUL_PROXY_ADDRESS;
    Integer proxyPort = DEFAUL_PROXY_PORT;
    //	    String errorJsonForSignatureCheck = "";

    static { // #1
        try {
            Provider kalkanProvider = new KalkanProvider();
            //Добавление провайдера в java.security.Security
            boolean exists = false;
            Provider[] providers = Security.getProviders();
            for (Provider p : providers) {
                if (p.getName().equals(kalkanProvider.getName())) {
                    exists = true;
                }
            }
            if (!exists) {
                Security.addProvider(kalkanProvider);
            } else {
                // да нужно заменять провайдер каждый раз когда загружается класс, иначе провайдер будет не доступен;
                Security.removeProvider(kalkanProvider.getName());
                Security.addProvider(kalkanProvider);
            }
            canWorkWithKalkan.set(true);
            providerName = kalkanProvider.getName();
            //System.out.println("SecureManager: provider = " + providerName); выводит KALKAN - ok
            // Почему Error, а не Exception -
            // чтобы поймать например ошибки когда провайдер скомпилированный под яву 1.7 запускаетьс на  яве 1.6
        } catch (Error ex) {
            logger.error("Can't load Kalkan provider: ", ex);
            kalkanErrorMessage = ex.getMessage();
            canWorkWithKalkan.set(false);
        }
    }

    static { //#2
        MAP_OF_LOAD_CRL_LABEL = new ConcurrentHashMap(); // описание состояния загрузки CRL-файлов
        MAP_OF_XCRL = new ConcurrentHashMap();  // последний версий загруженных CRL-файлов лежат здесь
        MAP_OF_LOAD_CRL_TIME = new ConcurrentHashMap();  // когда CRL-файлов загрузили в последний раз
        MAP_OF_CRL_PATH = new ConcurrentHashMap(); // путь для загрузки CRL-файлов , здесь в примере он захаркоден

        //MAP_OF_CRL_PATH.put(CRL_RSA_1, "http://crl.pki.gov.kz/rsa.crl");
        MAP_OF_CRL_PATH.put(CRL_RSA_1, props.getProperty("RSA_CERTS_PATH"));
        MAP_OF_CRL_PATH.put(CRL_RSA_2, props.getProperty("RSA_CERTS_PATH"));
        MAP_OF_CRL_PATH.put(CRL_GOST_1, props.getProperty("GOST_CERTS_PATH"));
        MAP_OF_CRL_PATH.put(CRL_GOST_2, props.getProperty("GOST_CERTS_PATH"));
        String[] clrsArray = {CRL_GOST_1, CRL_GOST_2, CRL_RSA_1, CRL_RSA_2};
        for (String crl : clrsArray) {
            MAP_OF_LOAD_CRL_LABEL.put(crl, TypeOfCrlLoaded.NO_LOAD); //инициализация - загрузки CRL-файлов еще не было
            MAP_OF_XCRL.put(crl, NO_OBJECT); //инициализация - соотвественно и самих CRL-файлов еще нет
        }
    }


    public SecureManager(String realBinIin, String respName, Integer respCode) {
        this.realBinIin = realBinIin;
        this.respName = respName;
        this.typeOfRespondent = TypeOfRespondent.findByCode(respCode);
    }

    public String getLastErrorMsg() {
        return verifyErrorMsg;
    }

    public void SetBrokerCode(String code) {
        this.BrokerCode = code;
    }


    public boolean isGoodSignature(String signedData, String signature) {
        if (!canWorkWithKalkan.get()) {
            verifyErrorMsg = "Kalkan provider didn't loaded:" + kalkanErrorMessage;
            logger.error(verifyErrorMsg);
            return false;
        }
        Boolean result = verifyCMSSignature(signature, signedData);
        return result;
    }

    private CMSSignedData createCMSSignedData(String sigantureToVerify, String signedData) throws CMSException, IOException {
        CMSSignedData cms = new CMSSignedData(Base64.decode(sigantureToVerify));
        boolean isAttachedContent = cms.getSignedContent() != null;
        if (isAttachedContent) {
            cms = new CMSSignedData(cms.getEncoded());
        } else {
            CMSProcessableByteArray data = new CMSProcessableByteArray(signedData.getBytes("UTF-8"));
            cms = new CMSSignedData(data, cms.getEncoded());
        }
        return cms;
    }

    /**
     * Основной метод который и проверяет валидность подписи данных
     *
     * @param sigantureToVerify - подпись
     * @param signedData        - данные
     * @return
     */
    public Boolean verifyCMSSignature(String sigantureToVerify, String signedData) {
        verifyErrorMsg = "Error is undefined.";
        try {
            CMSSignedData cms = createCMSSignedData(sigantureToVerify, signedData);
            SignerInformationStore signers = cms.getSignerInfos();
            CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", providerName);
            if (!reCheckClientSignature(signers, clientCerts)) {
                return false;
            }
	            
	            /*
	            if (isBadBinOrIin(signers, clientCerts)) {
	                return false;
	            }
	            */
            if (isBadKeyUsage(signers, clientCerts)) {
                return false;
            }

            try {
                if (checkNucOneCertificateType(signers, clientCerts)) {
                    return true;
                } else if (checkNucTwoCertificateType(signers, clientCerts)) {
                    return true;
                } else {
                    verifyErrorMsg = "Sign certificate not issued by NCA RK.";
                    logger.error(verifyErrorMsg);
                    return false;
                }
            } catch (Exception ex) {
                logger.error(verifyErrorMsg, ex);
                return false;
            }

        } catch (Exception e) {
            if ((e.getCause() instanceof SignatureException)) {
                verifyErrorMsg = "SIGNATURE_VALIDATION_ERROR : " + e.getMessage();
            } else {
                verifyErrorMsg = "COMMON_ERROR : " + e.getMessage();
            }
            logger.error(verifyErrorMsg, e);
            return false;
        }
    }


    private Certificate createCerificate_nuc2_gost() {
        return createCerificateByFile(pathCertNuc2Gost, "'НУЦ 2.0 ГОСТ'");
    }

    private Certificate createCerificate_nuc2_rsa() {
        return createCerificateByFile(pathCertNuc2Rca, "'НУЦ 2.0 RSA'");
    }

    private Certificate createCerificate_kuc_gost() {
        return createCerificateByFile(pathCertKucGost, "'КУЦ ГОСТ'");
    }

    private Certificate createCerificate_kuc_rsa() {
        return createCerificateByFile(pathCertKucRca, "'КУЦ RSA'");
    }

    private Certificate createCerificate_nuc1_gost() {
        return createCerificateByFile(pathCertNuc1Gost, "'НУЦ 1.0 ГОСТ'");
    }

    private Certificate createCerificate_nuc1_rsa() {
        return createCerificateByFile(pathCertNuc1Rca, "'НУЦ 1.0 RSA'");
    }

    private Certificate createCerificateByFile(String fileName, String storeDescript) {
        CertPath cp = null;
        try {
            InputStream inputStream = this.getClass().getResourceAsStream(fileName);
            if (inputStream == null) {
                logger.info("stream is null");
            }
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", providerName);
            cp = certFactory.generateCertPath(inputStream, "PKCS7");
            inputStream.close();
            //IOUtils.closeQuietly(fis);
        } catch (Exception ex) {
            throw new RuntimeException("createCerificateByFile ORE SIGN: Can't create certificate from storage '" + fileName + "' for " + storeDescript
                    + "." + ex.getMessage().toString(), ex);
        }

        List<? extends Certificate> certs = cp.getCertificates();
        if (certs.size() == 1) {
            //System.out.println("Создали сертификат " + fileName + " для " + storeDescript);
            return certs.get(0);
        } else {
            throw new RuntimeException("In storage '" + fileName + "' for " + storeDescript + " can be onlu one certificate, but found " + certs.size() + ".");
        }

    }

    public String getRespName() {
        return respName;
    }

    public void setRespName(String respName) {
        this.respName = respName;
    }

    public String getRealBinIin() {
        return realBinIin;
    }

    public void setRealBinIin(String realBinIin) {
        this.realBinIin = realBinIin;
    }

    public TypeOfRespondent getTypeOfRespondent() {
        return typeOfRespondent;
    }

    public void setTypeOfRespondent(TypeOfRespondent typeOfRespondent) {
        this.typeOfRespondent = typeOfRespondent;
    }

    public boolean differentBins(String bin_iin) {
        if (bin_iin.length() > 12) {
            bin_iin = bin_iin.substring(0, 12);
        }
        boolean result = !getRealBinIin().equals(bin_iin);
        return result;
    }

//	    public String getErrorJsonForSignatureCheck() {
//	        return errorJsonForSignatureCheck;
//	    }
    //
//	    public void setErrorJsonForSignatureCheck(String errorJsonForSignatureCheck) {
//	        this.errorJsonForSignatureCheck = errorJsonForSignatureCheck;
//	    }

    /**
     * Проверим то что сертификаты в подписи действительно подписали сообщение
     *
     * @param signers
     * @param clientCerts
     * @return
     */
    private boolean reCheckClientSignature(SignerInformationStore signers, CertStore clientCerts) throws
            CertStoreException, NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        Iterator it = signers.getSigners().iterator();

        boolean overAllResult = true;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            int indexOfSigner = 0;
            while (certIt.hasNext()) {
                indexOfSigner++;
                X509Certificate cert = (X509Certificate) certIt.next();
                SetCertInfo(cert);
                //log.info("------ Сертификат внутри подписи: " + indexOfSigner+ " ----- ");
                //log.info(cert.toString());
                try {
                    //проверка сертификатом внутри подписи
                    cert.checkValidity();
                    overAllResult = (overAllResult) && (signer.verify(cert, providerName));
                    //проверка сертификатом из базы ранее присланного
                    X509Certificate cert_db = GetCertFromBytes(GetCertFromDb(BrokerCode));
                    cert_db.checkValidity();
                    overAllResult = (overAllResult) && (signer.verify(cert_db, providerName));
                } catch (CertificateExpiredException ex) {
                    verifyErrorMsg = "Sign certificate expired.";
                    logger.error("ORE SIGN2: " + verifyErrorMsg, ex);
                    return false;
                } catch (CertificateNotYetValidException ex) {
                        verifyErrorMsg = "Sign certificate not valid more.";
                    logger.error("ORE SIGN3: " + verifyErrorMsg, ex);
                    return false;
                }
            }
            if (indexOfSigner == 0) {
                verifyErrorMsg = "Data is signed, but check certificate not found.";
                logger.info(verifyErrorMsg);
            }

            if (!overAllResult) {
                verifyErrorMsg = "Rechecking the data signature and certificate gave an error.";
                logger.info(verifyErrorMsg);
            }
        }
        return overAllResult;
    }

    /**
     * Проверка совподают ли БИН в подписи с тем БИНом котрый респодент зарегистрировался
     * в приложений. Здесь проверка всегда проходит успешно так как я в данном примере передаю правильный БИН в post-запросе
     * В реальной системе Вы можете например использовать другой сертификат для SSL-аутентификаций респондента
     * в этом случае БИНы могут не совподать.
     * Для эксперемента вы можете поменят БИН в этом пример когда посылаете post-запрос с браузера.
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean isBadBinOrIin(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        if (signers.getSigners().size() == 0) {
            verifyErrorMsg = "No sign in data.";
            logger.info(verifyErrorMsg);
            return true;
        }
        Iterator it = signers.getSigners().iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            //System.out.println(  );
            if (certCollection.size() == 0) {
                verifyErrorMsg = "No sign certificates in data.";
                logger.info(verifyErrorMsg);
                return true;
            }
            while (certIt.hasNext()) {
                X509Certificate cert = (X509Certificate) certIt.next();
                String subj = cert.getSubjectDN().getName();
                Pattern pt;
                Matcher m;
                if (typeOfRespondent.equals(TypeOfRespondent.FIRM)) {
                    pt = Pattern.compile("BIN(\\d{12})");
                    m = pt.matcher(subj); // get a matcher object
                    if (m.find()) {
                        if (realBinIin.equals(m.group(1))) {
                            return false;
                        } else {
                            verifyErrorMsg = "To sign data use certificate with BIN '" + realBinIin + "' , not this '" + m.group(1) + "'. ";
                            logger.info(verifyErrorMsg);
                        }
                    } else {
                        verifyErrorMsg = "BIN " + realBinIin + " not found in signed data certificate.";
                        logger.info(verifyErrorMsg);
                    }
                } else {
                    pt = Pattern.compile("IIN(\\d{12})");
                    m = pt.matcher(subj); // get a matcher object
                    if (m.find()) {
                        if (realBinIin.equals(m.group(1))) {
                            return false;
                        } else {
                            verifyErrorMsg = "To sign data use certificate with BIN '" + realBinIin + "' , not this '" + m.group(1) + "'. ";
                            logger.info(verifyErrorMsg);
                        }
                    } else {
                        verifyErrorMsg = "BIN " + realBinIin + " not found in signed data certificate.";
                        logger.info(verifyErrorMsg);
                    }
                }
            }
        }
        return true;
    }

    /**
     * Нужно чтобы у сертификата стояло свойство 'неотрекаемость'.
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean isBadKeyUsage(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        if (signers.getSigners().size() == 0) {
            verifyErrorMsg = "No signs in data.";
            logger.info(verifyErrorMsg);
            return true;
        }
        Iterator it = signers.getSigners().iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            if (certCollection.size() == 0) {
                verifyErrorMsg = "No certificates in signed data.";
                logger.info(verifyErrorMsg);
                return true;
            }
            while (certIt.hasNext()) {
                X509Certificate cert = (X509Certificate) certIt.next();
                //SetCertInfo(cert);
	                /*
	                Расширение 2.5.29.32
					Название: Политики применения
					Значение: [1]Политика сертификата приложения: [2]Политика сертификата приложения: 
					Идентификатор политики=Пользователь Центра Регистрации, HTTP, 
					TLS клиент [3]Политика сертификата приложения: Идентификатор политики=Проверка 
					подлинности клиента
	                 */
                String oid = "2.5.29.32";
                if (!GetExtensionValue(cert, oid))
                    return false;
                if (cert.getKeyUsage()[0] && cert.getKeyUsage()[1]) {
                    continue;
                } else {
                    verifyErrorMsg = "To sign must use certificate with key 'Non repudiation'.";
                    logger.info(verifyErrorMsg);
                    return false;
                }
            }
        }
        return false;
    }

    /**
     * Проверка подписи на то что она подписана сертификатом от системы НУЦ_1 и
     * если да то проверка отозванности сертификата
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean checkNucOneCertificateType(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        Iterator it = signers.getSigners().iterator();
        boolean result = false;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            if (certCollection.size() == 0) {
                throw new RuntimeException("No certificates in signed data.");
            }
            while (certIt.hasNext()) {
                X509Certificate userCert = (X509Certificate) certIt.next();
                X509Certificate certForCheck = null;
                boolean isMyVersion = false;
                try {
                    if (TypeOfRespondent.FIRM.equals(typeOfRespondent)) {
                        X509Certificate certNuc1Gost = (X509Certificate) createCerificate_nuc1_gost();
                        userCert.verify(certNuc1Gost.getPublicKey(), providerName);
                        certForCheck = certNuc1Gost;
                    } else {
                        X509Certificate certNuc1Rsa = (X509Certificate) createCerificate_nuc1_rsa();
                        userCert.verify(certNuc1Rsa.getPublicKey(), providerName);
                        certForCheck = certNuc1Rsa;
                    }

                    isMyVersion = true;
                } catch (Exception ex) {
                    //log.info("Не подписан сертификатом старого типа НУЦ 1");
                    logger.info(ex.getMessage().toString());
                    result = false;
                }
                if (isMyVersion) { // если данные были подписанный сертфикатом от системы НУЦ_1 то
                    try {
                        certForCheck.checkValidity(); // проверяем валидность сертификата
                    } catch (CertificateExpiredException ex) {
                        throw new RuntimeException("Data signed with certificate NCA 1.0, but root certificate is deprecated.");
                    } catch (CertificateNotYetValidException ex) {
                        throw new RuntimeException("Data signed with certificate NCA 1.0, but root certificate is not valid more.");
                    }
                    try {
                        if (isNotRevokedCertNucOne(userCert)) {  // проверяем отозваность сертификата
                            return true;
                        } else {
                            throw new RuntimeException("Sign certificate is recalled.");
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException(ex.getMessage());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Проверка подписи на то что она подписана сертификатом от системы НУЦ_2 и
     * если да то проверка отозванности сертификата
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean checkNucTwoCertificateType(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        Iterator it = signers.getSigners().iterator();
        boolean result = false;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            //System.out.println(  );
            if (certCollection.size() == 0) {
                throw new RuntimeException("No certificates in signed data.");
            }
            while (certIt.hasNext()) {
                X509Certificate userCert = (X509Certificate) certIt.next();
                boolean isMyVersion = false;
                X509Certificate certForCheck = null;
                try {
                    if (TypeOfRespondent.FIRM.equals(typeOfRespondent)) {
                        X509Certificate certNuc2Gost = (X509Certificate) createCerificate_nuc2_gost();
                        X509Certificate certKucGost = (X509Certificate) createCerificate_kuc_gost();
                        userCert.verify(certNuc2Gost.getPublicKey(), providerName);
                        certNuc2Gost.verify(certKucGost.getPublicKey(), providerName);
                        certForCheck = certNuc2Gost;
                    } else {
                        X509Certificate certNuc2Rsa = (X509Certificate) createCerificate_nuc2_rsa();
                        X509Certificate certKucRsa = (X509Certificate) createCerificate_kuc_rsa();
                        userCert.verify(certNuc2Rsa.getPublicKey(), providerName);
                        certNuc2Rsa.verify(certKucRsa.getPublicKey(), providerName);
                        certForCheck = certNuc2Rsa;
                    }

                    isMyVersion = true;
                } catch (Exception ex) {
                    result = false;
                    logger.info(ex.getMessage().toString());
                }
                if (isMyVersion) { // если данные были подписанный сертфикатом от системы НУЦ_1 то
                    try {
                        certForCheck.checkValidity();
                    } catch (CertificateExpiredException ex) {
                        throw new RuntimeException("Data signed with certificate NCA 2.0, but root certificate is deprecated.");
                    } catch (CertificateNotYetValidException ex) {
                        throw new RuntimeException("Data signed with certificate NCA 2.0, but root certificate is not valid more.");
                    }

                    try {
                        if (isNotRevokedCertNucTwo(userCert)) {
                            result = true;
                            return true;
                        } else {
                            throw new RuntimeException("Sign certificate is recalled.");
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException(ex.getMessage());
                    }
                }
            }
        }
        return result;
    }

    public String getPathCertNuc1Gost() {
        return pathCertNuc1Gost;
    }

    public void setPathCertNuc1Gost(String pathCertNuc1Gost) {
        this.pathCertNuc1Gost = pathCertNuc1Gost;
    }

    public String getPathCertNuc1Rca() {
        return pathCertNuc1Rca;
    }

    public void setPathCertNuc1Rca(String pathCertNuc1Rca) {
        this.pathCertNuc1Rca = pathCertNuc1Rca;
    }

    public String getPathCertNuc2Gost() {
        return pathCertNuc2Gost;
    }

    public void setPathCertNuc2Gost(String pathCertNuc2Gost) {
        this.pathCertNuc2Gost = pathCertNuc2Gost;
    }

    public String getPathCertNuc2Rca() {
        return pathCertNuc2Rca;
    }

    public void setPathCertNuc2Rca(String pathCertNuc2Rca) {
        this.pathCertNuc2Rca = pathCertNuc2Rca;
    }

    public String getPathCertKucGost() {
        return pathCertKucGost;
    }

    public void setPathCertKucGost(String pathCertKucGost) {
        this.pathCertKucGost = pathCertKucGost;
    }

    public String getPathCertKucRca() {
        return pathCertKucRca;
    }

    public void setPathCertKucRca(String pathCertKucRca) {
        this.pathCertKucRca = pathCertKucRca;
    }


    /**
     * отзыв сертификатов для физиков находятся в CRL-файле для RSA отзыв
     * сертификаты для юриков находятся в CRL-файле для GOST
     *
     * @param currentRespType - тип респондента физическое лицо или юридическое
     * @param versionPkiSdk   - Какой сертификат используеться НУЦ_1 или НУЦ_2
     * @return
     */
    private String findCurrentCrlName(TypeOfRespondent currentRespType, int versionPkiSdk) {
        if (versionPkiSdk == 1) {
            if (TypeOfRespondent.FIRM.equals(currentRespType)) {
                return CRL_GOST_1;
            } else {
                return CRL_RSA_1;
            }
        } else if (versionPkiSdk == 2) {
            if (TypeOfRespondent.FIRM.equals(currentRespType)) {
                return CRL_GOST_2;
            } else {
                return CRL_RSA_2;
            }
        } else {
            throw new RuntimeException("Recall check not found for " + currentRespType.toString() + " and version PKI SDK =" + versionPkiSdk);
        }
    }

    /**
     * Нужно ли подгружать из инета CRL-файл или нет ?
     *
     * @param crlName
     * @return
     */
    private boolean isNeedLoadCrlObject(String crlName) {
        if (TypeOfCrlLoaded.NO_LOAD.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            return true; // да, если его еще не загружали
        } else if (TypeOfCrlLoaded.LOADING.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            return false; // нет, если загрузку начали но она не завершилась
        } else if (TypeOfCrlLoaded.LOADED.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            Date currentDt = new Date();
            Date lastLoadedCrl = MAP_OF_LOAD_CRL_TIME.get(crlName);
            Date checkDt = DateUtils.addHours(lastLoadedCrl, HOURS_OF_RELOAD);
            if (checkDt.before(currentDt)) {
                return true;  // да, если последняя загрузка произошла HOURS_OF_RELOAD часов тому назад
            } else {
                return false;
            }
        } else {
            throw new RuntimeException("Conditions for status not defined " + MAP_OF_LOAD_CRL_LABEL.get(crlName));
        }
    }


    /**
     * Загрузка CRL-файла с инета, так как у меня прокси , то пришлось писать
     * код и для него
     *
     * @param crlName
     */
    private void loadCrlObject(String crlName) {
        //log.info("loadCrlObject");
        TypeOfCrlLoaded oldState = MAP_OF_LOAD_CRL_LABEL.get(crlName);
        if (TypeOfCrlLoaded.LOADING.equals(oldState)) {
            return;
        }
        MAP_OF_LOAD_CRL_LABEL.put(crlName, TypeOfCrlLoaded.LOADING);
        String location = MAP_OF_CRL_PATH.get(crlName);
        try {
	        	/*
	            URL url = new URL(location);
	            HttpURLConnection conn = null;
	            if (useProxy) {
	                Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddress, proxyPort));
	                conn = (HttpURLConnection) url.openConnection(proxy);
	            } else {
	                conn = (HttpURLConnection) url.openConnection();
	            }
	            conn.setUseCaches(false);
	            conn.setDoInput(true);
	            conn.connect();
	            if (conn.getResponseCode() == 200) {
	            */
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "KALKAN");
            //crlName = CRL_GOST_1

            String path = props.getProperty("GOST_CERTS_PATH");

            //System.err.println(SecureManager.class.getResourceAsStream("/resources/crl/gost.crl") != null);
            //System.err.println(SecureManager.class.getClassLoader().getResourceAsStream("./resources/crl/gost.crl") != null);

            InputStream inStream = new FileInputStream(path);
            //InputStream inStream = SecureManager.class.getResourceAsStream(path);
            //SecureManager.class.getResourceAsStream(path)
            //X509CRL crlObject = (X509CRL) cf.generateCRL(conn.getInputStream());
            X509CRL crlObject = (X509CRL) cf.generateCRL(inStream);
            MAP_OF_XCRL.put(crlName, crlObject);
	             
	        /* }
	           else {
	                String msg = "Ошибка(1) получения CRL-файла : '" + location
	                        + "' : " + conn.getResponseCode() + " ,  " + conn.getResponseMessage();
	                log.warning(msg);
	            } */
        } catch (Exception e) {
            logger.error("Error (1) getting CRL-file : '", e);
        }
        //MAP_OF_LOAD_CRL_LABEL.put(crlName, oldState ) ;
        MAP_OF_LOAD_CRL_TIME.put(crlName, new Date());
        MAP_OF_LOAD_CRL_LABEL.put(crlName, TypeOfCrlLoaded.LOADED);
    }

    /**
     * Найти CRL-файл для проверки на отозваность
     *
     * @param versionPkiSdk
     * @return null - возможен
     */
    private X509CRL findCrlObject( //X509Certificate certForCheck, X509Certificate userCert,
                                   int versionPkiSdk) {
        //log.info("findCrlObject");
        String crlName = findCurrentCrlName(typeOfRespondent, versionPkiSdk);
        if (isNeedLoadCrlObject(crlName)) {
            //log.info(crlName);
            loadCrlObject(crlName);
        }
        Object result = MAP_OF_XCRL.get(crlName);
        if (result.equals(NO_OBJECT)) {
            logger.warn("Recall check not found for " + crlName);
            return null;
        }
        return (X509CRL) result;
    }

    /**
     * Проверка на отозваность сертификата в системе НУЦ_1
     *
     * @param userCert
     * @return
     */
    private boolean isNotRevokedCertNucOne(X509Certificate userCert) {
        X509CRL crlObject = findCrlObject(1);
        if (crlObject != null) {
            return !(crlObject.isRevoked(userCert));
        } else {
            return true;
        }
    }

    /**
     * Проверка на отозваность сертификата в системе НУЦ_2
     *
     * @param userCert
     * @return
     */
    private boolean isNotRevokedCertNucTwo(X509Certificate userCert) {
        X509CRL crlObject = findCrlObject(2);
        if (crlObject != null) {
            return !(crlObject.isRevoked(userCert));
        } else {
            return true;
        }
    }

    public Boolean getUseProxy() {
        return useProxy;
    }

    public void setUseProxy(Boolean useProxy) {
        this.useProxy = useProxy;
    }

    public String getProxyAddress() {
        return proxyAddress;
    }

    public void setProxyAddress(String proxyAddress) {
        this.proxyAddress = proxyAddress;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    void setUseProxy(String property) {
        Boolean value = Boolean.valueOf(property);
        setUseProxy(value);
    }

    void setProxyPort(String property) {
        Integer value = Integer.valueOf(property);
        setProxyPort(value);
    }

    static public DERObject toDERObject(byte[] data) throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream DIS = new ASN1InputStream(inStream);
        return DIS.readObject();
    }

    public boolean GetExtensionValue(X509Certificate cert, String oid) {
        byte[] UID = cert.getExtensionValue(oid);
        try {
            DERObject derObject = toDERObject(UID);
            if (derObject instanceof DEROctetString) {
                DEROctetString derOctetString = (DEROctetString) derObject;
                derObject = toDERObject(derOctetString.getOctets());
                if (derObject.toString().indexOf("http://pki.gov.kz/cps") != -1)
                    return true;
            }
        } catch (Exception ex) {
            //log.info(ex.getMessage().toString());
            return false;
        }
        return false;
    }

    public void ReadDb() {
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName("com.mysql.jdbc.Driver");
            logger.info("Connecting to database...");
            conn = DriverManager.getConnection(url, user, password);
            logger.info("Creating statement...");
            stmt = conn.createStatement();
            String sql;
            sql = "SELECT full_name from brokers";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                //int id  = rs.getInt("id");
                logger.info("Full name: " + rs.getString("full_name"));
            }
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }// nothing we can do
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }//end finally try
        }//end try
    }

    public byte[] GetCertFromDb(String login) {
        Connection conn = null;
        Statement stmt = null;
        Blob cert = null;
        byte[] b = null;
        try {
            Class.forName("com.mysql.jdbc.Driver");
            //log.info("Connecting to database...");
            conn = DriverManager.getConnection(url, user, password);
            //log.info("Creating statement...");
            stmt = conn.createStatement();
            String sql;
            sql = "SELECT certfile from users where login = '" + login + "'";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                //int id  = rs.getInt("id");
                cert = rs.getBlob("certfile");
                //File image = new File("D:\\java.gif");
                //FileOutputStream fos = new FileOutputStream(image);
                //log.info(cert);
            }
            rs.close();
            stmt.close();
            conn.close();
            b = cert.getBytes(1, (int) cert.length());
            return b;
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }// nothing we can do
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }//end finally try
        }//end try
        return b;
    }

    public X509Certificate GetCertFromBytes(byte[] cert) {
        X509Certificate myCert = null;
        try {
            myCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(cert));
            //log.info(myCert.toString());
            return myCert;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return myCert;
    }

    public void ShowCertContent(byte[] cert) {
        try {
            Certificate myCert = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(cert));
            logger.info(myCert.toString());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void DbSaveCertInfo(String login, String msg, String signature, String certinfo, boolean check_status) {
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName("com.mysql.jdbc.Driver");
            conn = DriverManager.getConnection(url, user, password);
            stmt = conn.createStatement();
            String sql;
            sql = "insert into msg (login, msg, signature, certinfo, created, check_status) values (?, ?, ?, ?, ?, ?);";
            PreparedStatement preparedStmt = conn.prepareStatement(sql);
            preparedStmt.setString(1, login);
            preparedStmt.setString(2, msg);
            preparedStmt.setString(3, signature);
            preparedStmt.setString(4, certinfo);
            //Calendar calendar = Calendar.getInstance();
            //java.sql.Date startDate = new java.sql.Date(calendar.getTime().getTime());
            //preparedStmt.setDate (5, startDate);
            preparedStmt.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
            preparedStmt.setBoolean(6, check_status);
            preparedStmt.execute();
            preparedStmt.close();
            conn.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
            }// nothing we can do
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }//end finally try
        }//end try
    }

    private void SetCertInfo(X509Certificate userCert) {
        String info = null;
        info = "--------------Certificate information-----------------";
        info += userCert.getVersion() + "\n";
        info += userCert.getSerialNumber().toString(16) + "\n";
        info += userCert.getSubjectDN() + "\n";
        info += userCert.getIssuerDN() + "\n";
        info += userCert.getNotBefore() + "\n";
        info += userCert.getNotAfter() + "\n";
        info += userCert.getSigAlgName() + "\n";
        this.certinfo += info;
    }

    public String GetMsgFromDb(String id) {
        String data = null;
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName("com.mysql.jdbc.Driver");
            conn = DriverManager.getConnection(url, user, password);
            stmt = conn.createStatement();
            String sql;
            sql = "SELECT msg from msg where id = " + id + ";";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                data = rs.getString("msg");
            }
            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            logger.info(e.getMessage().toString());
        }
        return data;
    }

    public X509Certificate GetCertFromCMSString(String cms_data) {
        X509Certificate cert = null;
        return cert;
    }

    public Boolean verifyCMSSignatureNew(byte [] signedData, byte [] data, Provider provider) {
        CMSUtil cmsUtil = new CMSUtil();
        try {
            cmsUtil.verifyCMS(signedData, data, provider);
            logger.info("CMS signed data is verified.");
            return true;
        } catch (ProviderUtilException e) {
            logger.error("CMS signed data verify error: ", e);
        }
        return false;
    }

    public Provider getProvider()   {
        // Инициализация провайдера
        Provider kalkanProvider = new KalkanProvider();
        //Добавление провайдера в java.security.Security
        boolean exists = false;
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().equals(kalkanProvider.getName())) {
                exists = true;
            }
        }
        if (!exists) {
            Security.addProvider(kalkanProvider);
        }
        // Для дальнейшего использования наименования провайдера определяется
        //1
        //String providerName = kalkanProvider.getName();
        //2 или
        //providerName = KalkanProvider.PROVIDER_NAME;
        return kalkanProvider;
    }

}