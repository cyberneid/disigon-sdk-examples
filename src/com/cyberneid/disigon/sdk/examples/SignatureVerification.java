package com.cyberneid.disigon.sdk.examples;

import java.io.FileInputStream;

import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.VerificationResult;
import com.cyberneid.disigon.sdk.VerifySignatureHelper;

/**
 *  @author UgoChirico
 *  https://www.ugochirico.com
 *  https://www.cyberneid.com
 */
public class SignatureVerification {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {    	
    	// the input file
		String input = "Lorem Ipsum.pdf.p7m";
				
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		// set licensee and product key
		// contact us at https://www.cyberneid.com to get a lincese key
		Disigon.setLicense("<licensee>", "<productkey>");
		
		
		try 
        {
			FileInputStream ins = new FileInputStream(input);
							
			VerifySignatureHelper.init();
			 
			VerifySignatureHelper vsh = new VerifySignatureHelper();
			
			VerificationResult vr = vsh.verify(ins);
			
			ins.close();
			
			System.out.println(vr.toString());
        }
		 catch(Exception ex)
		 {
			 ex.printStackTrace();
		 }
    }
	
}
