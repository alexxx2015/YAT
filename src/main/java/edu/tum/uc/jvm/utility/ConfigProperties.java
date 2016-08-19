package edu.tum.uc.jvm.utility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

public final class ConfigProperties {
	private static String configFile;
	
	public static enum PROPERTIES{
		ANALYSIS_REPORT
		, PDP_PORT, PDP_HOST
		, PIP_PORT, PIP_HOST
		, PMP_PORT, PMP_HOST
		, MYPEP_HOST, MYPEP_PORT
		, INSTRUMENTED_CLASS_PATH
		, ENFORCEMENT
		, STATISTICS
		, BLACKLIST
		, WHITELIST
		, INSTRUMENTATION
		, TIMER_T1
		, TIMER_T2
		, TIMER_T3
		, TIMER_T4
		, TIMER_T5
		, NETCOM
		, UC_PROPERTIES
		, PDP_ASYNCOM
		, UC4WIN_AUTOSTART
		, IFT
	}
	
	private static Properties CONFIGURATION = null;	
	
	public static void setConfigFile(String file){
		configFile = file;
		CONFIGURATION= null;
	}
	
	public static String getProperty(PROPERTIES string){
		if(CONFIGURATION == null){
			if(configFile == null)
				configFile = "/uc.config";
			URL ucConfig = ConfigProperties.class.getResource(configFile);
			////System.out.println(ucConfig);
			File f = new File(configFile);
			if(ucConfig != null){
				f = new File(ucConfig.getFile());
			}
//			File f = new File("./uc.config");
			////System.out.println(""+ f + f.exists());
			if(f.exists()){
				try {
					FileInputStream fis = new FileInputStream(f);
					CONFIGURATION = new Properties();
					CONFIGURATION.load(fis);
//					BufferedReader br = new BufferedReader(new FileReader(f));
//					String line;
//					while((line = br.readLine()) != null){
//						String[] lineCmp = line.split(":");
//						if(lineCmp.length == 2){
//							ConfigProperties.CONFIGURATION.put(lineCmp[0].trim(), lineCmp[1].trim());
//						}
//					}
				} catch (FileNotFoundException e) {
					// TODO Auto-generPROPERTIESated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		////System.out.println(string);
		////System.out.println(CONFIGURATION);
		String _return = CONFIGURATION.getProperty(string.toString());
 		return _return;
	}	
}
