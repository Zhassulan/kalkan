package kz.ets.eds;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore;
import kz.gov.pki.kalkan.util.Arrays;
import kz.gov.pki.kalkan.util.encoders.Base64;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import sun.security.x509.Extension;

import org.apache.commons.lang3.time.DateUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.mysql.jdbc.Blob;

public class TheMain {

	public static void main(String[] args) {
		
		String login = args[0];
		//String login = "EVTB";
		//String PlainData = "Hi, how are you?";
		String PlainData = args[1];
        //String signedPlainData = "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";
        String signedPlainData = args[2];
                
        
        SecureManager sm = new SecureManager("123456789011", "", 1); //2-PERSON, 1 - FIRM
        //sm.ReadDb();
        
        //ShowCertContent(sm.GetCertFromDb("EVTB"));
        
        
        Boolean b = sm.isGoodSignature(PlainData, signedPlainData);
        sm.DbSaveCertInfo(login, PlainData, signedPlainData, sm.certinfo, b);
        if (b) 
        	{
        	System.out.println(b);
        	}
        else 
        	{
        	System.out.println(b);
        	}	
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
	
	public static void ShowCertContent(byte [] cert)	{
		 try {
                //CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate myCert = CertificateFactory.getInstance("X509").generateCertificate(new 					ByteArrayInputStream(cert));
                //FileInputStream in = new FileInputStream(str_cert);
                //X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                //in.close();
                System.out.println("Cert from db: " + myCert);
            	}	
            catch(Exception ex)
            	{
                ex.printStackTrace();
            	}
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
                    System.out.println("Bad signature: Element 'ds:Reference' is not found in XML document");
                }
                XMLSignature signature = new XMLSignature(sigElement, "");
                KeyInfo ki = signature.getKeyInfo();
                
                String certfilename = "resources/testov_test.cer";
                //X509Certificate cert1 = ki.getX509Certificate();
                
                //try	{
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    //Certificate cert1 = cf.generateCertificate(new FileInputStream(certfilename));
                    FileInputStream is = new FileInputStream (certfilename);
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
              	if (m.find())
              		{
              		iinbin = m.group(1);
              		//System.out.println(iinbin);
                    }
              	
                //String realBinIin, String respName, Integer respCode
                //SecureManager sm = new SecureManager()
                
                String filename = "resources/testov_test.cer";
              
                try 
	    	        {
	            	String content = new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
	            	
	    	        }
	            catch (IOException e) 
	    	        {
	            	e.printStackTrace();
	    	        }
                
                if (cert != null) {
                    result = signature.checkSignatureValue(cert2);
                    rootEl.removeChild(sigElement);
                    
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
}
