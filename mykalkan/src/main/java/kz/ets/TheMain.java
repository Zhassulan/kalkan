package main.java.eds;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import kz.gov.pki.kalkan.util.encoders.Base64;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class TheMain {

	private final static Charset UTF8_CHARSET = Charset.forName("UTF-8");
	
	public static void main(String[] args) {
		
		boolean mode = false; //true - продуктивный режим
		String login = null;
		String PlainData = null;
		String signedPlainData = null;
		//String msg_id = null;
		
		//System.out.println("args[1]: " + args[1] + " :args[1]." );
		if (mode)
			{
			login = args[0];
			
			byte[] valueDecoded = null;
			try {
				valueDecoded = Base64.decode(args[1].getBytes());	
				PlainData = new String(valueDecoded);
				}
			catch (Exception e)
				{
				System.out.println(e.getMessage().toString());
				}
			
			//PlainData = args[1];
			signedPlainData = args[2];
			}
		else
			{
			login = "EVTB";
			PlainData = "Hi, how are you?";
			signedPlainData = "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";
			}
        
        SecureManager sm = new SecureManager("123456789011", "", 1); //2-PERSON, 1 - FIRM
        
        //sm.log.info("Plain data: " + PlainData + " :Plain data.");
        //sm.log.info("Signed data: " + signedPlainData + " :Signed data.");
        
        sm.SetBrokerCode(login);
        //PlainData = sm.GetMsgFromDb(msg_id);
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
