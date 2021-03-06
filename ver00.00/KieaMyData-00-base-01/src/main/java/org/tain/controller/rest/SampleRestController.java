package org.tain.controller.rest;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.tain.tools.node.MonJsonNode;
import org.tain.utils.IpPrint;
import org.tain.utils.StringTools;

import SK.Utility.UCPIDResponse;
import SK.Utils.ClientUtils;
import SK.Utils.RequestUtils;
import SK.Utils.ResponseUtils;
import SK.Utils.StatusUtils;
import SK.Utils.VarUtils;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/rest")
@Slf4j
public class SampleRestController {

	/*
	 * curl -X POST -H "Content-Type: application/json" -d @./test.json http://localhost:8080/v0.1/rest/test
	 */
	@CrossOrigin(origins="*", methods = {RequestMethod.GET, RequestMethod.POST}, maxAge = 3600)
	@RequestMapping(value = {"/test"}, method = {RequestMethod.GET, RequestMethod.POST})
	public ResponseEntity<?> test(HttpEntity<String> httpEntity) throws Exception {
		MonJsonNode nodeReq = null;
		if (Boolean.TRUE) {
			HttpHeaders headers = httpEntity.getHeaders();
			String body = httpEntity.getBody();
			nodeReq = new MonJsonNode(body == null ? "{}" : body);
			log.info(">>>>> ip.info: " + IpPrint.get());
			log.info(">>>>> request.headers: " + headers.toString());
			log.info(">>>>> request.body: " + body);
			log.info(">>>>> request.body.JSON: " + nodeReq.toPrettyString());
		}
		
		MonJsonNode nodeRes = new MonJsonNode("{}");
		if (Boolean.TRUE) {
			testJob(nodeReq, nodeRes);
		}
		
		MultiValueMap<String,String> headers = null;
		if (Boolean.TRUE) {
			headers = new LinkedMultiValueMap<>();
			headers.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8");
		}
		//return new ResponseEntity<>(nodeRes.getJsonNode(), headers, HttpStatus.OK);
		return new ResponseEntity<>("Hello world!!!", headers, HttpStatus.OK);
	}
	
	//@SuppressWarnings("unused")
	private void testJob(MonJsonNode nodeReq, MonJsonNode nodeRes) throws Exception {
		
		if (Boolean.TRUE) {
			nodeRes.put("name", "Hello, workd!!!");
			log.info(">>>>> mapRes: {}", nodeRes);
		}
		
		// 1. data from request
		String person_encoded = "??????????????? ?????????????????? ????????? signed_personInfoReq url-safe encoding ??? ???";
		String consent_encoded = "??????????????? ?????????????????? ????????? signed_consentInfo url-safe encoding ??? ???";
		if (Boolean.TRUE) {
			int index = 0;
			person_encoded = nodeReq.getText("/signedDataList/" + index, "signedPersonInfoReq");
			consent_encoded = nodeReq.getText("/signedDataList/" + index, "signedConsent");
			log.info(">>>>> 1. person_encoded: {}", person_encoded);
			log.info(">>>>> 1. consent_encoded: {}", consent_encoded);
		}
		
		// 2. ?????? ??????(?????? ?????????????????????)??? ?????? ?????? ????????? ?????? ????????? ??????
		String personInfoForVerify = VarUtils.get_data_for_CMSVerify(person_encoded);
		String consentInfoForVerify = VarUtils.get_data_for_CMSVerify(consent_encoded);
		if (Boolean.TRUE) {
			log.info(">>>>> 2. personInfoForVerify: {}", personInfoForVerify);
			log.info(">>>>> 2. consentInfoForVerify: {}", consentInfoForVerify);
		}
		
		// 3. url-safe decoding
		byte[] signed_personInfoReq = VarUtils.base64_url_decoding(person_encoded);
		byte[] signed_consentInfo = VarUtils.base64_url_decoding(consent_encoded);
		if (Boolean.TRUE) {
			log.info(">>>>> 3. signed_personInfoReq:");
			StringTools.printHex(signed_personInfoReq);
			log.info(">>>>> 3. signed_consentInfo:");
			StringTools.printHex(signed_consentInfo);
		}
		
		// 4. ??? ?????? ??????????????? ????????? byte ??? ??????
		byte[] personCert = ClientUtils.get_certificate_from_cms(signed_personInfoReq);
		byte[] consentCert = ClientUtils.get_certificate_from_cms(signed_consentInfo);
		if (Boolean.TRUE) {
			log.info(">>>>> 4. personCert:");
			StringTools.printHex(personCert);
			log.info(">>>>> 4. consentCert:");
			StringTools.printHex(consentCert);
		}
		
		// 5. ??? ?????? ??????????????? nonce??? ??????
		String ucpidNonceInCms = ClientUtils.get_ucpidNonce_from_signedPersonInfoReq(signed_personInfoReq);
		String consentNonceInCms = ClientUtils.get_consentNonce_from_signdConsentInfo(signed_consentInfo);
		if (Boolean.TRUE) {
			log.info(">>>>> 5. ucpidNonceInCms: {}", ucpidNonceInCms);
			log.info(">>>>> 5. consentNonceInCms: {}", consentNonceInCms);
		}
		
		String ucpidNonceInApi = "??????????????? ?????????????????? api-002??? ?????? ?????? ?????? ucpidNonce ???";
		String consentNonceInApi = "??????????????? ?????????????????? api-002??? ?????? ?????? ?????? consentNonce ???";
		
		if (Boolean.TRUE || (ucpidNonceInCms.equals(ucpidNonceInApi) && consentNonceInCms.equals(consentNonceInApi))) {
			if (isSameCertificate(personCert, consentCert)) {
				if (isVerifyingOK()) {
					VarUtils.setPropertiesPath("config_data/route.properties");
					
					String _ucpIdNonce = "?????????????????? ?????? ????????? ucpIdNonce ???";
					String _cpCode = "??????????????? ????????????";
					String _cpRequestNumber = "????????????????????????????????? ?????? tx_id ???";
					String _ca_code = "????????????????????????????????? ?????? ???????????? ????????????";
					String _signCertPath = VarUtils.getResourceFromProperty("signCert");
					byte[] _certificate = VarUtils.getFromFile(_signCertPath);
					
					if ("SignKorea".equals(_ca_code)) {
						byte[] bUCPIDRequest = RequestUtils.getUCPIDRequest(
								_ucpIdNonce
								, _cpCode
								, _cpRequestNumber
								, _certificate
								, signed_personInfoReq
								, 1);
						byte[] bUCPIDResponse = null;
						
						if (Boolean.TRUE) {
							log.info(">>>>> request to ucpid server is started.");
							
							String serverIp = "211.175.81.101"; //koscom ucpid test server ip
							int serverPort = 8098; //koscom ucpid test server port
							bUCPIDResponse = request2UCPID(bUCPIDRequest, serverIp, serverPort);  // connect to the server
							
							log.info(">>>>> request to ucpid server is successfully done.");
						}
						
						String status = ResponseUtils.getStatusCode(bUCPIDResponse);
						if (StatusUtils.isOk(status)) {
							UCPIDResponse ucpidResponse = ResponseUtils.getInstance(bUCPIDResponse);
							
							int version = ucpidResponse.getVersion();
							String UCPIDNonce = ucpidResponse.getUcpidNonce();
							String cpRequestNumber = ucpidResponse.getCpRequestNumber();
							String certDn = ucpidResponse.getCertDn();
							String cpCode = ucpidResponse.getCpCode();
							String di = ucpidResponse.getDi();
							String realName = ucpidResponse.getRealName();
							int gender = ucpidResponse.getGender();
							int natinalInfo = ucpidResponse.getNationalInfo();
							String birthDate = ucpidResponse.getBirthDate();
							int ciUpdate = ucpidResponse.getCiUpdate();
							String ci = ucpidResponse.getCi();
							String ci2 = ucpidResponse.getCi2();
						} else {
							log.info("your UCPIDResponse is invalid. your error code is \"" + status + "\"");
						}
					}
				}
			}
		}
	}

	private boolean isVerifyingOK() {
		return true;
	}

	private boolean isSameCertificate(byte[] personCert, byte[] consentCert) {
		return true;
	}
	
	private byte[] request2UCPID(byte[] UCPIDRequest, String serverIp, int serverPort) {
		
		Socket socket = null;
		DataInputStream reader = null;
		DataOutputStream writer = null;
		byte[] UCPIDResponse = null;
		
		try {
			socket = new Socket(serverIp, serverPort);
			if (socket != null) {
				if (socket.isConnected()) {
					writer = new DataOutputStream(socket.getOutputStream());
					if (writer != null) {
						writer.writeInt(UCPIDRequest.length);
						writer.write(UCPIDRequest, 0, UCPIDRequest.length);
						writer.flush();
					}
					reader = new DataInputStream(socket.getInputStream());
					if (reader != null) {
						int readInt = reader.readInt();
						UCPIDResponse = new byte[readInt];
						reader.readFully(UCPIDResponse);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (socket != null) socket.close();
				if (writer != null) writer.close();
				if (reader != null) reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return UCPIDResponse;
	}
}
