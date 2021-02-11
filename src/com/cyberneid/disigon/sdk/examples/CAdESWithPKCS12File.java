package com.cyberneid.disigon.sdk.examples;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import com.cyberneid.disigon.sdk.CACertStore;
import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.P12Signer;
import com.cyberneid.disigon.sdk.P7MDocument;
import com.cyberneid.disigon.sdk.SimpleCertSelector;
import com.cyberneid.disigon.sdk.util.FileUtil;
import com.qequipe.p11.Certificate;

public class CAdESWithPKCS12File {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {    	
    	// the input file
		String input = "test.xml";
		
		// the output file
		String output = "test.p7m";
		
		String password = "12348765";
		
				
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		Disigon.setAddCACertificate(true);
		
		
		try
		{
			X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X509").generateCertificate(new FileInputStream("cacert.cer"));
			
			CACertStore.getInstance().addCertificate(cert);

			FileInputStream fins = new FileInputStream("Ornellina.p12");
			
			// creates a new instance of P12Signer with the given pkcs12 file			
			P12Signer dsign = new P12Signer(fins);
	
			// open a new session with the HSM
			dsign.open();

			// login
			dsign.login(password);
			
			FileInputStream inputFileStream = new FileInputStream(input);
			ByteArrayOutputStream bouts = new ByteArrayOutputStream();
			FileUtil.copy(inputFileStream, bouts);
			
			P7MDocument sigDoc = dsign.sign(bouts.toByteArray(), new SimpleCertSelector(false), true, false, false);
		
			FileOutputStream fouts = new FileOutputStream(output);
			
			fouts.write(sigDoc.toDER());
			fouts.close();
			
			System.out.println("done");
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		} 
    }
}
