package com.cyberneid.disigon.sdk.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import com.cyberneid.disigon.sdk.ByLabelCertSelector;
import com.cyberneid.disigon.sdk.CertSelector;
import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.P11Signer;
import com.cyberneid.disigon.sdk.QualifiedCertSelector;
import com.cyberneid.disigon.sdk.XAdESGenerator;

public class XAdESWithAWSCloudHSM {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {
		// the pkcs#11 module to be used 
		String module = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"; // AWS CloudHSM
    	
    	// the input file
		String input = "test.xml";
		
		// the output file
		String output = "test.signed.xml";
		
		// the pin in the form of <CU_user_name>:<password>
		String pin = "CryptoUser:CUPassword123!";
		
		
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		// set true if you want to add the CA certificate to the p7m
		Disigon.setAddCACertificate(true);
		
		// set licensee and product key
		// contact us at https://www.cyberneid.com to get a lincese key
		Disigon.setLicense("<licensee>", "<productkey>");
		
				
		try
		{
			// creates a new instance of P11Signer with the given pkcs11 module
			// you may specify your own PKCS#11 dll
			P11Signer dsign = new P11Signer(module);
	
			// open a new session with the HSM
			dsign.open();

			// determine how many active slots are available
			int slotCount = dsign.getSlotsCount(true);		
			System.out.println("slot count: " + slotCount);
			
			// specify the slot 0. Change the index if you want to use another slot
			dsign.setSlot(0);
			
			// login
			dsign.login(pin);
			
			// XAdES generator for generating the XAdES signature
			XAdESGenerator xadesGen = new XAdESGenerator();
			xadesGen.load(input);
			
			// Certificate Selector for selecting the certificate
			CertSelector certSelector;
			
			if(CERTIFICATE_BY_PATH)
			{
				// Certificate Selector for selecting the certificate stored the file system 
				// at the given path
				// Set the id to match your signature id key as stored in the HSM
				// and set the path to the certificate to be used for signature				
				certSelector = new AWSHSMCertSelector("private key id", "/opt/cert.der");
			}
			else
			{
				// Certificate Selector for selecting the certificate stored in the HSM 
				// with a given label
				// set the label to match your signature certificate's label as stored
				// in the HSM
				certSelector = new ByLabelCertSelector("myCertificateLabel");
			}
			// sign Xades BES
			Document document = xadesGen.signBES(dsign,certSelector, null);
			
			// write to file
			writeXMLToFile(document, output);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		} 
    }
	
	private static void writeXMLToFile(Document doc, String outputPath) throws TransformerFactoryConfigurationError, TransformerException, IOException {
        Source source = new DOMSource(doc);

        File outFile = new File(outputPath);
        FileOutputStream fos = new FileOutputStream(outFile);

        StreamResult result = new StreamResult(fos);

        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        xformer.transform(source, result);

        fos.close();
    }
}
