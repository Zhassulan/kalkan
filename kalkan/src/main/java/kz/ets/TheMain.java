package kz.ets;

import com.sun.org.apache.xpath.internal.operations.Bool;
import kz.gov.pki.kalkan.util.encoders.Base64;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.security.Provider;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TheMain {

    //private final static Charset UTF8_CHARSET = Charset.forName("UTF-8");
    private static Logger logger = LogManager.getLogger(TheMain.class);
    private static PropsManager props = PropsManager.getInstance();

    public static void main(String[] args) {
        boolean mode = Boolean.valueOf(props.getProperty("PROD"));
        boolean result = false;
        String login = null;
        String plainData = null;
        String signedPlainData = null;
        logger.info("Production mode is " + mode);
        if (mode) {
            try {
                login = args[0];
                plainData = args[1];
                signedPlainData = args[2];
                logger.info("JAR arguments: args[1] = " + args[1] + ", args[1] = " + args[1] + ", args[2] = " + args[2]);
            } catch (Exception e)   {
                logger.error("Error: ", e);
                logger.info("Check result is " + result);
                return;
            }
        } else {
            login = props.getProperty("TEST.LOGIN");
            plainData = props.getProperty("TEST.PLAIN_DATA");
            signedPlainData = props.getProperty("TEST.SIGNED_PLAIN_DATA");
        }
        SecureManager sm = new SecureManager(props.getProperty("TEST.BIN"), "", 1); //2-PERSON, 1 - FIRM
        Provider provider = sm.getProvider();
        sm.SetBrokerCode(login);
        //plainData = sm.GetMsgFromDb(msg_id);
        //sm.ReadDb();
        //ShowCertContent(sm.GetCertFromDb("EVTB"));

        //Boolean b = sm.isGoodSignature(plainData, signedPlainData);
        logger.info("Broker login: " + login);
        logger.info("Plain data: " + plainData);
        logger.info("Checking decoded plain data: " + new String(Base64.decode(plainData.getBytes())));
        logger.info("Checking signed data: " + signedPlainData);
        logger.info("Provider name: " + provider.getName());
        result = sm.verifyCMSSignatureNew(Base64.decode(signedPlainData.getBytes()), Base64.decode(plainData.getBytes()), provider);
        sm.DbSaveCertInfo(login, plainData, signedPlainData, sm.certinfo, result);
        logger.info("Check result is " + result);
        /*
		Provider kalkanProvider = new KalkanProvider();
        boolean exists = false;
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().equals(kalkanProvider.getName())) {
                exists = true;
                System.out.println(kalkanProvider.getName());
            }
        }
        if (!exists) {
            Security.addProvider(kalkanProvider);
        }
        
        String providerName = kalkanProvider.getName();
        System.out.println("Provider: " + providerName);
        
        String filename = "resources/signed_xml.txt";
        //InputStream is= TheMain.class.getClass().getResourceAsStream("/resources/signed_xml.txt");
        try 
	        {
        	String content = new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
            //System.out.println(content);
            boolean b = verifyXml(content);
            System.out.println("VERIFICATION RESULT IS: " + b);
	        }
        catch (IOException e) 
	        {
        	e.printStackTrace();
	        }
	       */
    }

    //для примера
    public static boolean verifyXml(String xmlString) {
        boolean result = false;
        try {
            Init.init();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));

            Element sigElement = null;
            Element rootEl = (Element) doc.getFirstChild();

            NodeList list = rootEl.getElementsByTagName("ds:Signature");
            int length = list.getLength();
            for (int i = 0; i < length; i++) {
                Node sigNode = list.item(length - 1);
                sigElement = (Element) sigNode;
                if (sigElement == null) {
                    logger.error("Bad signature: Element 'ds:Reference' is not found in XML document");
                }
                XMLSignature signature = new XMLSignature(sigElement, "");
                KeyInfo ki = signature.getKeyInfo();

                String certfilename = props.getProperty("TEST.PERSON_CERT");
                //X509Certificate cert1 = ki.getX509Certificate();

                //try	{
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                //Certificate cert1 = cf.generateCertificate(new FileInputStream(certfilename));
                FileInputStream is = new FileInputStream(certfilename);
                X509Certificate cert2 = (X509Certificate) cf.generateCertificate(is);
                //System.out.println("Cert from file: " + cert1);
                	/*}	
                catch(Exception ex)
                	{
                    ex.printStackTrace();
                	}
                */

                X509Certificate cert = ki.getX509Certificate();
                //System.out.println(cert.getSubjectDN());
                //System.out.println(cert.getSerialNumber());

                String subj = cert.getSubjectDN().getName();
                //System.out.println(cert.getPublicKey());

                //Pattern pt = Pattern.compile("BIN(\\d{12})");
                Pattern pt = Pattern.compile("IIN(\\d{12})");
                Matcher m = pt.matcher(subj); // get a matcher object
                String iinbin = null;
                if (m.find()) {
                    iinbin = m.group(1);
                    //System.out.println(iinbin);
                }

                //String realBinIin, String respName, Integer respCode
                //SecureManager sm = new SecureManager()
                String filename = props.getProperty("TEST.PERSON_CERT");

                try {
                    String content = new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");

                } catch (IOException e) {
                    logger.error("Error: ", e);
                }

                if (cert != null) {
                    result = signature.checkSignatureValue(cert2);
                    rootEl.removeChild(sigElement);
                }
            }
        } catch (Exception e) {
            logger.error("Error", e);
        }
        return result;
    }

}
