package org.tain.tools.properties;

import java.io.FileInputStream;
import java.util.Properties;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class MyDataAuthProperties {

	private Properties prop = null;
	
	@Bean
	public void start() throws Exception {
		log.info(">>>>> START of MyDataAuthProperties <<<<< ");
		
		String propertiesFile = System.getProperty("mydata.config.file", "/Users/kang-air/KANG/mydata/MyDataAuth.properties");
		log.info(">>>>> propertiesFile: " + propertiesFile);
		
		this.prop = new Properties();
		this.prop.load(new FileInputStream(propertiesFile));
		String lstOrg = this.prop.getProperty("param.lstOrg");
		String daemon = this.prop.getProperty("param.daemon");
		String routeFile = this.prop.getProperty("file.route");
		String storeAuthUrl = this.prop.getProperty("store.auth.url");
		
		// KANG20211022: add
		String useNonce = this.prop.getProperty("use.nonce", "false");
		String useOrgCode = this.prop.getProperty("use.orgCode", "false");
		String useTxId = this.prop.getProperty("use.txId", "false");
		String useStoreAuth = this.prop.getProperty("use.store.auth", "false");
		String svrCertPasswd = this.prop.getProperty("svr.cert.password", "11223344");
		
		log.info(">>>>> lstOrg: " + lstOrg);
		log.info(">>>>> daemon: " + daemon);
		log.info(">>>>> routeFile: " + routeFile);
		log.info(">>>>> storeAuthUrl: " + storeAuthUrl);
		
		// KANG20211022: add
		log.info(">>>>> useNonce      : " + useNonce);
		log.info(">>>>> useOrgCode    : " + useOrgCode);
		log.info(">>>>> useTxId       : " + useTxId);
		log.info(">>>>> useStoreAuth  : " + useStoreAuth);
		log.info(">>>>> svrCertPasswd : " + svrCertPasswd);
	}
	
	public String get(String key) {
		return this.prop.getProperty(key);
	}
	
	public String get(String key, String defValue) {
		return this.prop.getProperty(key, defValue);
	}
}
