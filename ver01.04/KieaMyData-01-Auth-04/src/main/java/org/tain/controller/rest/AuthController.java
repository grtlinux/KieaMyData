package org.tain.controller.rest;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.tain.tools.httpClient.MonHttpClient;
import org.tain.tools.node.MonJsonNode;
import org.tain.tools.properties.MyDataAuthProperties;
import org.tain.utils.IpPrint;
import org.tain.utils.StringTools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.signkorea.sign.SKSignedDataInfo;
import com.signkorea.sign.SKVerifyExtInfo;
import com.signkorea.sign.SKVerifyc;

import SK.Exception.ErrorCode;
import SK.Exception.MydataException;
import SK.Utility.UCPIDResponse;
import SK.Utils.ClientUtils;
import SK.Utils.RequestUtils;
import SK.Utils.ResponseUtils;
import SK.Utils.VarUtils;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/rest")
@Slf4j
public class AuthController {

	//@Autowired
	//private ProjEnvParam projEnvParam;
	
	@Autowired
	private MyDataAuthProperties prop;
	
	@Autowired
	private MonHttpClient monHttpClient;
	
	/*
	 * curl -X POST -H "Content-Type: application/json" -d @./1test.json http://localhost:8080/v0.1/rest/auth
	 */
	@CrossOrigin(origins="*", methods = {RequestMethod.POST}, maxAge = 3600)
	@RequestMapping(value = {"/auth"}, method = {RequestMethod.GET, RequestMethod.POST})
	public ResponseEntity<?> autu01(HttpEntity<String> httpEntity) throws Exception {
		MonJsonNode nodeReq = null;
		if (Boolean.TRUE) {
			/*
			 * Request
			 */
			HttpHeaders headers = httpEntity.getHeaders();
			String body = httpEntity.getBody();
			nodeReq = new MonJsonNode(body == null ? "{}" : body);
			log.info(">>>>> ip.info: " + IpPrint.get());
			log.info(">>>>> request.headers: " + headers.toString());
			log.info(">>>>> request.body: " + body);
			log.info(">>>>> request.body.JSON: " + nodeReq.toPrettyString());
		}
		
		if (Boolean.TRUE) {
			/*
			 * ArrayNode TEST
			 */
			JsonNode jsonNode = nodeReq.getJsonNode();
			ArrayNode arrNode = (ArrayNode) jsonNode.at("/signedDataList");
			if (arrNode.isArray()) {
				System.out.println(">>>>> arrNode.size(): " + arrNode.size());
				System.out.println(">>>>> arrNode.get(0).orgCode: " + arrNode.get(0).get("orgCode").textValue());
				JsonNode node = arrNode.get(0);
				System.out.println(">>>>> node.orgCode: " + node.get("orgCode").asText("SignKorea"));
				
			} else {
				System.out.println(">>>>> no array");
			}
		}
		
		String orgName = null;
		String orgIp = null;
		int orgPort = 0;
		if (Boolean.TRUE) {
			/*
			 * 인증기관 선택
			 */
			String ca_code = nodeReq.getText("caOrg");
			if (ca_code == null)
				ca_code = "SignKorea";
			
			String[] org = this.prop.get("param.lstOrg").split(",");
			for (int i=0; i < org.length; i++) {
				if (org[i].contains(ca_code)) {
					String strInfo = org[i];
					String[] arrItem = strInfo.split("_");
					System.out.println(">>>>> org:" + arrItem[0] + ", ip:" + arrItem[1] + ", port:" + arrItem[2]);
					orgName = arrItem[0];
					orgIp = arrItem[1];
					orgPort = Integer.parseInt(arrItem[2]);
					break;
				}
			}
		}
		
		Map<String,Object> mapRet = new HashMap<>();
		if (Boolean.TRUE) {
			/*
			 * 각각 인증처리를 한다.
			 */
			List<Map<String,Object>> lstRes = new ArrayList<>();
			JsonNode jsonNode = nodeReq.getJsonNode();
			ArrayNode arrNode = (ArrayNode) jsonNode.at("/signedDataList");
			System.out.println(">>>>> arrayNode.size = " + arrNode.size());
			for (int idx = 0; idx < arrNode.size(); idx ++) {
				JsonNode nodeIn = arrNode.get(idx);
				Map<String,Object> mapOut = testJob03(nodeIn, orgName, orgIp, orgPort);
				lstRes.add(mapOut);
			}
			
			mapRet.put("list", lstRes);
		}
		
		MultiValueMap<String,String> headers = null;
		if (Boolean.TRUE) {
			headers = new LinkedMultiValueMap<>();
			headers.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8");
		}
		return new ResponseEntity<>(mapRet, headers, HttpStatus.OK);
	}
	
	private Map<String,Object> testJob03(JsonNode nodeIn, String orgName, String orgIp, int orgPort) throws Exception {
		Map<String,Object> mapOut = new HashMap<>();
		
		String person_encoded = null; //"마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_personInfoReq의 url-encoding된 값";
		String consent_encoded = null; //"마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_consentInfo의 url-encoding된 값";
		person_encoded = nodeIn.get("signedPersonInfoReq").asText();
		consent_encoded = nodeIn.get("signedConsent").asText();
		System.out.println(">>>>> person_encoded = " + person_encoded);
		System.out.println(">>>>> consent_encoded = " + consent_encoded);
		
		/* 1. url-decoding */
		byte[] signed_personInfoReq = VarUtils.base64_url_decoding(person_encoded);
		byte[] signed_consentInfo = VarUtils.base64_url_decoding(consent_encoded);

		/* 2. 검증 데몬에 인자값으로 넣기 위한 포맷의 서명 데이터 획득 */
		String personInfoForVerify = VarUtils.get_data_for_CMSVerify(person_encoded);
		String consentInfoForVerify = VarUtils.get_data_for_CMSVerify(consent_encoded);

		/* 3. 각 서명 데이터에서 인증서 byte 값 획득  */
		byte[] personCert = ClientUtils.get_certificate_from_cms(signed_personInfoReq);
		byte[] consentCert = ClientUtils.get_certificate_from_cms(signed_consentInfo);

		/*  4. 각 서명 데이터에서 nonce 값 획득 */
		String ucpidNonceInCms = ClientUtils.get_ucpidNonce_from_signedPersonInfoReq(signed_personInfoReq);
		String consentNonceInCms = ClientUtils.get_consentNonce_from_signdConsentInfo(signed_consentInfo);
		
		/* 5. 마이데이터 사업자로부터 전달 받은 nonce 값 저장 */
		//String ucpidNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 ucpidNonce 값";
		//String consentNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 consentNonce 값";

		/* 각 서명데이터의 서명시간(Date형) 획득 */
		Date SigningTimeUCPID = (Date) ClientUtils.getSigningTime(signed_personInfoReq);
		Date SigningTimeConset = (Date) ClientUtils.getSigningTime(signed_consentInfo);

		/* 각 서명데이터의 서명시간(String형) 획득 */
		String SigningTimeUCPID_STR = ClientUtils.getSigningTime_str(signed_personInfoReq);
		String SigningTimeConset_STR = ClientUtils.getSigningTime_str(signed_consentInfo);
		
		//if(ucpidNonceInCms.equals(ucpidNonceInApi) && consentNonceInCms.equals(consentNonceInApi)){ /* Nonce 값이 동일할 경우 (재전송 공격 방지) */
		{
				//if(isSameCertificate(personCert,consentCert)){ /* 두 서명 데이터에서 사용된 인증서가 동일할 경우 <- 해당 인증서 비교 함수는 정보제공자가 개발필요 */
				{
					/*
					 * 위의 personInfoForVerify, consentInfoForVerify 값을 검증데몬 혹은 검증라이브러리에 파라미터값으로 넣어 서명 검증 실시.
						personInfoForVerify - 검증
						consentInfoForVerify(전송요구내역) - 검증 후 원문확인
					 */
					if (isVerifyingOk(personInfoForVerify) && isVerifyingOk(consentInfoForVerify)) {
						/* 검증데몬에서 서명데이터의 검증이 정상적으로 성공하였을 경우 */
						//VarUtils.setPropertiesPath("./config/route.properties");/*properties 파일 설정(절대 경로 혹은 상대경로)*/
						VarUtils.setPropertiesPath(this.prop.get("file.route"));/*properties 파일 설정(절대 경로 혹은 상대경로)*/
						
						//String ucpidNonce = "정보제공자가 직접생성한 ucpidNonce";
						//String ucpidNonce = ucpidNonceInCms;
						String ucpidNonce = StringTools.getNonce();
						ucpidNonce = Base64.encodeBase64URLSafeString(ucpidNonce.getBytes());
						
						//String cpCode ="정보제공자 cpCode (한국정보인증에 신청)"; // Test cpCode C0123456789A(ispurl www.mydata.co.kr)
						String cpCode = "C0123456789A";
						//String cpCode = nodeIn.get("orgCode").asText("C0123456789A");
						//String cpRequestNumber = "마이데이터사업자로부터 받은 tx_id 값";
						String cpRequestNumber = "123459";
						//String ca_code ="마이데이터사업자로부터 받은 인증기관 기관코드"; // SignKorea / yessign / KICA / CrossCert
						
						//String ca_code = (String) mapIn.get("caOrg");
						//if (ca_code == null)
						//	ca_code = "SignKorea";
						
						//person_encoded = nodeIn.get("signedPersonInfoReq").asText();
						try{
							String signCertPath = VarUtils.getResourceFromProperty("signCert");
							byte[] certificate = VarUtils.getFromFile(signCertPath);
							VarUtils.setCertPassword("11223344");	//서버인증서 비밀번호
							
							/*
							String serverIp = "";
							int serverPort = 0;
							
							if("SignKorea".equals(ca_code)){
								serverIp = "211.175.81.101";
								serverPort = 8098;
							}
							else if("yessign".equals(ca_code)){
								serverIp = "203.233.91.231";
								serverPort = 4719;
							}
							else if("KICA".equals(ca_code)){
								serverIp = "121.254.188.161";
								serverPort = 9090;
							}
							else if("CrossCert".equals(ca_code)){
								serverIp = "203.248.34.63";
								serverPort = 17586;
							}
							*/
							
							/* UCPID 서버로 보내기 위한 메시지 생성*/
							byte[] UCPIDRequest = RequestUtils.getUCPIDRequest(ucpidNonce, cpCode, cpRequestNumber, certificate, signed_personInfoReq, 1);
							/* UCPID 서버로 UCPIDRequest Message 전송 및 UCPIDResponse 획득 */
							byte[] bUCPIDResponse = request2UCPID(UCPIDRequest, orgIp, orgPort);
							
							String status = ResponseUtils.getStatusCode(bUCPIDResponse);
							System.out.println(">>>>> status = " + status);
							if ("OK".equals(status)){
								UCPIDResponse ucpidResponse = ResponseUtils.getInstance(bUCPIDResponse);
								
								int version = ucpidResponse.getVersion();
								String UCPIDNonce = ucpidResponse.getUcpidNonce();
								String CpRequestNumber = ucpidResponse.getCpRequestNumber();
								String certDn = ucpidResponse.getCertDn();
								String CpCode = ucpidResponse.getCpCode();
								String di = ucpidResponse.getDi();
								String realName = ucpidResponse.getRealName();
								int gender = ucpidResponse.getGender();
								int nationalInfo = ucpidResponse.getNationalInfo();
								String birthDate = ucpidResponse.getBirthDate();
								/*
									ciupdate가 홀수일경우 ci이용 짝수일경우 ci2이용
									ex) ciupdate=1 ci이용
										ciupdate=2 ci2이용
										ciupdate=3 ci이용
										ciupdate=4 ci2이용
								*/
								int ciupdate = ucpidResponse.getCiUpdate();
								String ci = ucpidResponse.getCi();
								String ci2 = ucpidResponse.getCi2();
								
								System.out.println("personInfo's version ==============> " + version);
								System.out.println("personInfo's UCPIDNonce ===========> " + UCPIDNonce);
								System.out.println("personInfo's cpRequestNumber ======> " + CpRequestNumber);
								System.out.println("personInfo's certDn ===============> " + certDn);
								System.out.println("personInfo's cpCode ===============> " + CpCode);
								System.out.println("personInfo's Di ===================> " + di);
								System.out.println("personInfo's realName =============> " + realName);
								System.out.println("personInfo's gender ===============> " + gender);
								System.out.println("personInfo's nationalInfo =========> " + nationalInfo);
								System.out.println("personInfo's birthDate ============> " + birthDate);
								System.out.println("personInfo's ciupdate =============> " + ciupdate);
								System.out.println("personInfo's ci ===================> " + ci);
								System.out.println("personInfo's ci2 ==================> " + ci2);
								
								mapOut.put("version", version);
								mapOut.put("UCPIDNonce", UCPIDNonce);
								mapOut.put("CpRequestNumber", CpRequestNumber);
								mapOut.put("certDn", certDn);
								mapOut.put("CpCode", CpCode);
								mapOut.put("di", di);
								mapOut.put("realName", realName);
								mapOut.put("gender", gender);
								mapOut.put("nationalInfo", nationalInfo);
								mapOut.put("birthDate", birthDate);
								mapOut.put("ciupdate", ciupdate);
								mapOut.put("ci", ci);
								mapOut.put("ci2", ci2);
								
								// TODO: store auth data of SUCCESS
								String storeAuthUrl = this.prop.get("store.auth.url");
								if (storeAuthUrl != null && !"".equals(storeAuthUrl)) {
									String strJson = new ObjectMapper().writeValueAsString(mapOut);
									System.out.println(">>>>> JSON: " + strJson);
									this.monHttpClient.post(storeAuthUrl, strJson);
								}
							}
							else{
								System.out.println("your UCPIDResponse is invalid. your error code is \"" + status + "\"");
								// TODO: store auth data of FAIL-1
							}
						}catch(MydataException e){
							// TODO: store auth data of FIAL-2
							/**
							 *
								서명데이터(UCPIDRequest)가 잘못된경우로 동일로직으로 처리하여도 무관함
								PARAMETER_EMPTY_IN_FUNCTION  / ERROR_IN_BYTE_TO_SEQUENCE / EMPTY_RETURN_VALUE_FROM_FUNCTION / INVALID_STRUCTURE
							 */
							if (ErrorCode.PARAMETER_EMPTY_IN_FUNCTION == e.getErrCode()){
								// 함수에 인자값이 null일 경우
								System.out.println("PARAMETER_EMPTY_IN_FUNCTION");
							} else if(ErrorCode.ERROR_IN_BYTE_TO_SEQUENCE == e.getErrCode()){
								// byte 값을 sequence로 변환실패
								System.out.println("ERROR_IN_BYTE_TO_SEQUENCE");
							} else if(ErrorCode.EMPTY_RETURN_VALUE_FROM_FUNCTION == e.getErrCode()){
								// 함수로부터 리턴받은 값이 null일 경우
								System.out.println("EMPTY_RETURN_VALUE_FROM_FUNCTION");
							} else if(ErrorCode.INVALID_STRUCTURE == e.getErrCode()){
								// 서명데이터의 asn.1 구조가 잘못된 경우
								System.out.println("INVALID_STRUCTURE");
							} else if(ErrorCode.NOT_INVALID_VALUE == e.getErrCode()){
								// UCPID Version이 다른경우 (version 2)
								System.out.println("NOT_INVALID_VALUE");
							} else if(ErrorCode.EMPTY_VALUE_IN_PROPERTIES == e.getErrCode()){
								//route.properties의 변수명이 다를경우
								System.out.println("EMPTY_VALUE_IN_PROPERTIES");
							}
							System.out.println(">> " + e.getMessage() + ", " + e.getErrCode());
						}catch(Exception e){
							e.printStackTrace();
						}
					} else{
						System.out.println("CMS Verify not ok");
					}
				}
				//else{
				//	System.out.println("isSameCertificate not ok");
				//}
		}
		//else{
		//	System.out.println("Nonce not ok");
		//}
		
		return mapOut;
	}
	
	private boolean isVerifyingOk(String signdataPEM) throws IOException
	{
		String strInfo = this.prop.get("param.daemon");
		String[] strItem = strInfo.split("_");
		
		int ret;
		String	demon_ip = strItem[0];  /* 데몬이 실행되어있는 서버 IP */
		int	demon_port = Integer.parseInt(strItem[1]);  /* 실행된 데몬 port */
		
		System.out.println(">>>>> demon: " + demon_ip + ":" + demon_port + (demon_port == 0 ? " -> SKIP" : " -> VERIFY"));
		if (demon_port == 0)
			return Boolean.TRUE;
		
		/* 검증할 CMS 서명데이터 */
		//String signdataPEM = "MIIIDgYJKoZIhvcNAQcCoIIH/zCCB/sCAQExDzANBglghkgBZQMEAgEFADBLBgkqhkiG9w0BBwGgPgQ8eyJjb25zZW50Ijoi6rOE7KKMIOygleuztC4uLiIsImNvbnNlbnROb25jZSI6ImRqVkpxU1NtdWpBUyJ9oIIFoDCCBZwwggSEoAMCAQICAwhZYzANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJLUjESMBAGA1UECgwJU2lnbktvcmVhMRUwEwYDVQQLDAxBY2NyZWRpdGVkQ0ExGzAZBgNVBAMMElNpZ25Lb3JlYSBUZXN0IENBNTAeFw0yMTA1MDQwNjQ1MDBaFw0yMjA1MDQxNDU5NTlaMIGDMQswCQYDVQQGEwJLUjESMBAGA1UECgwJU2lnbktvcmVhMRgwFgYDVQQLDA/thYzsiqTtirjsl4XsooUxGDAWBgNVBAsMD+2FjOyKpO2KuO2ajOyCrDEYMBYGA1UECwwP7YWM7Iqk7Yq47KeA7KCQMRIwEAYDVQQDDAlNeURhdGFfSkgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ4PA9KqUJAZ45eVN3/K2jgOmgazCJ8qbgVOymlgwoFZMEmGCUolrw9L/emzSGY7KMc7LZ7ulocTWvvTckc/MaRH+3C599WfEsZZCB9iAdCIVOX3ZsF639VcJf5R8W4wzTpX3Bdfvxfb+uLYmanEaPmugRkALUpKo+3qgwNID9z/7JVOLg71eZqyQrzd/RwaXlUBQFsD+pFHgAQGRnEs6JJiyBLj/Lsg2ZEgr8w3HEle3jfnzUh5lQymVnRVnfOXNIG6a8MkwJg4yk5dcNXVmyKiazBTqrySUydlIU3xmgPaHiLoBTIRBe0IRkMFqMuEkS83XP4uVSdvDJu8Ule431AgMBAAGjggJEMIICQDCBkwYDVR0jBIGLMIGIgBTxcKmvb8+di6yBhcwW9HzZhVwMxKFtpGswaTELMAkGA1UEBhMCS1IxDTALBgNVBAoMBEtJU0ExLjAsBgNVBAsMJUtvcmVhIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IENlbnRyYWwxGzAZBgNVBAMMEktpc2EgVGVzdCBSb290Q0EgN4IBBTAdBgNVHQ4EFgQUklhBVLWHqj4ys/4CDWUcLJWP0+EwDgYDVR0PAQH/BAQDAgbAMHsGA1UdIAEB/wRxMG8wbQYKKoMajJpEBQEBBTBfMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3LnNpZ25rb3JlYS5jb20vY3BzLmh0bWwwLgYIKwYBBQUHAgIwIh4gx3QAIMd4yZ3BHAAgwtzV2MapACDHeMmdwRzHhbLIsuQwaAYDVR0RBGEwX6BdBgkqgxqMmkQKAQGgUDBODAlNeURhdGFfSkgwQTA/BgoqgxqMmkQKAQEBMDEwCwYJYIZIAWUDBAIBoCIEIIu87wGZ2NpHtqJpIeoGSwAblt6VHE3mT2/uu+ydbl6EMFYGA1UdHwRPME0wS6BJoEeGRWxkYXA6Ly8yMTEuMTc1LjgxLjEwMjo2ODkvb3U9ZHAxMXAxMixvdT1BY2NyZWRpdGVkQ0Esbz1TaWduS29yZWEsYz1LUjA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6Ly8yMTEuMTc1LjgxLjEwMS9vY3NwLnBocDANBgkqhkiG9w0BAQsFAAOCAQEAgg/6m1Gqd6/LT2tji3IjjnQqXPdulJQoxTkPIytt2FLLX17VnMyjCW7ZwaF4ynG6lyAP+SQbK8qEvAhy8qOw7kUiFu2UGRDh6QySU1WoeVmg7qCqln2BkSiMJ+UjdAqmd4bdDpx15wGmj63DU7Fk9pcqsMF74nmnJ6VfURIicXTRNMUotmgRkp16kvpQ12wymxVaXhwV2bQMSMYKLkNizXbhyh3sEVyvVbYv02k4F0aQXkfR4HfSdK5BKVX3XBUvaKG5SQL1vWEaooP73rkx8HrY/zV73d5nQqLMVKDIPr5RMitLGZ+iQMLA9CV0DiZkGS58I3QwdUIKxG+KEYmoYjGCAfIwggHuAgEBMFwwVTELMAkGA1UEBhMCS1IxEjAQBgNVBAoMCVNpZ25Lb3JlYTEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRswGQYDVQQDDBJTaWduS29yZWEgVGVzdCBDQTUCAwhZYzANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDUxMzA1NTUyNVowLwYJKoZIhvcNAQkEMSIEIOSSFWjx8rEl5Wzpow6iYjjnrUx5MWFQP9B/nZBHJoRVMA0GCSqGSIb3DQEBAQUABIIBAIjewhz5GCNQu2mdj6P7oXemNzcT+f1Z5d823gdL78ZgBNbLEIAuwiFAp6Tqben7QHBxKodEVrzKkESSep97vvTUY1JvAy2/6A7l4tTrfm+mWmFd2e//QElByKVHacpQvtH3JXvXJDcHurEnKhp60Et7Zg8mGlod5ZjcpwTzt0TPkNbs2uOcOZrm/ndYyh3G4MKinSXdS37Elj9JjdaM10cRn3IfJaZo4AjGuj8vZZP8eKcJ7QgpoO60cAksFsB9kRouLYF7OJ9uPofk8jZAywjEXuNrwzQgwgAhrumX85DxhGf+/MaJfblOtV89Ix1Kw6VVSGuJVb3IZsm09f10PWw=";
		
		SKVerifyc        verifyc   = new SKVerifyc();  /* 데몬 통신 클래스 */
		SKSignedDataInfo data_info = new SKSignedDataInfo(); /* 검증할 데이터를 입력받는 클래스 */
		SKVerifyExtInfo  ext        = new SKVerifyExtInfo(); /* 검증후 인증서 세부정보가 담기는 클래스 */
		
		/***************************************************************************************
		verifySignCipher
		data_info.opcode = 58
		***************************************************************************************/
		
		System.out.println("\n********************************************************************");
		System.out.println("CMS verify");

		data_info.opcode = 58;  /* CMS verify(CRL 검증) opcode */
		data_info.signed_data = signdataPEM.getBytes();
		ret = verifyc.verifySignExt(demon_ip, demon_port, data_info, ext);
		if (ret == 0) {
			System.out.println("[58 verify OK]");
			String tmp = new String(data_info.bplaintext, "UTF-8"); // 검증결과 전송요구내역
			System.out.println("plaintext        : " + tmp);
			return Boolean.TRUE;
		} else {
			String tmp = new String(data_info.berrmsg, "euc-kr");
			System.out.println("["+ tmp +"]");
			return Boolean.FALSE;
		}
	}
	
	private byte[] request2UCPID(byte[] UCPIDRequest, String serverIp, int serverPort) {
	
		System.out.println(">>>>> " + serverIp + ":" + serverPort);
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
	
	////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////
	@Deprecated
	private Map<String,Object> testJob02(MonJsonNode nodeReq) throws Exception {
		Map<String,Object> mapRes = new HashMap<>();
		
		String person_encoded = null; //"마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_personInfoReq의 url-encoding된 값";
		String consent_encoded = null; //"마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_consentInfo의 url-encoding된 값";
		person_encoded = "MIIIsAYJKoZIhvcNAQcCoIIIoTCCCJ0CAQExDzANBglghkgBZQMEAgEFADCB0gYJKoZIhvcNAQcBoIHEBIHBMIG-AgECBBAxMjM0NTY3ODkwMTIzNDU2MF8MWeuPmeydmO2VqeuLiOuLpC4gYWJjZGVmZ2hpamtsbm1vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xOTU9QUVJTVFVWV1hZWjEyMzQ1Njc4OSAhQCMkJV4mKigpAwID-DA0DCJTaWduS29yZWEgVUNQSUQgVG9vbGtpdCBmb3IgbW9iaWxlDAZLT1NDT00wBgIBAgIBAQwQd3d3Lm15ZGF0YS5jby5rcqCCBbowggW2MIIEnqADAgECAgMIYmkwDQYJKoZIhvcNAQELBQAwVTELMAkGA1UEBhMCS1IxEjAQBgNVBAoMCVNpZ25Lb3JlYTEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRswGQYDVQQDDBJTaWduS29yZWEgVGVzdCBDQTUwHhcNMjEwNzA4MDgzNDAwWhcNMjIwNzA4MTQ1OTU5WjCBkDELMAkGA1UEBhMCS1IxEjAQBgNVBAoMCVNpZ25Lb3JlYTEYMBYGA1UECwwP7YWM7Iqk7Yq47JeF7KKFMRgwFgYDVQQLDA_thYzsiqTtirjtmozsgqwxGDAWBgNVBAsMD-2FjOyKpO2KuOyngOygkDEfMB0GA1UEAwwWU2lnbktvcmVhX015RGF0YV9Vc2VyMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANXdPWJd_4tlC0larbybZHCeB5oJOs22nhA3nt508NnOKxTwx4iyiZxuNR-xLVKGUfF23X76K9Rc2VGVQIyYwmKWfwFxCC9xUl6EBtniOg-o-ENMFWqF2fiwMQ3hWqcO4wd8nKHNxZRgQ8HhAqUC3vM46tOISdMXzvUHsSToua5Si8DZ4zA1ybjfKS3iyV9GuVb1d1yfH_pP_JmXGEugP72uDGJsx2nz8de8TPKZj2WzvPRJagsFmhnIkrMKKvLzQ6CrBx4LHaMQUUv5H3mFAJKV0T5yF7kTF9lGgN0j2f98JHElnFyfQpDHaFo9OOlLK7jlHc9y99GGxMmtO4WRFA0CAwEAAaOCAlEwggJNMIGTBgNVHSMEgYswgYiAFPFwqa9vz52LrIGFzBb0fNmFXAzEoW2kazBpMQswCQYDVQQGEwJLUjENMAsGA1UECgwES0lTQTEuMCwGA1UECwwlS29yZWEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgQ2VudHJhbDEbMBkGA1UEAwwSS2lzYSBUZXN0IFJvb3RDQSA3ggEFMB0GA1UdDgQWBBR_MQT93GRYSM5-p9G3LfOO-qZ5kDAOBgNVHQ8BAf8EBAMCBsAwewYDVR0gAQH_BHEwbzBtBgoqgxqMmkQFAQEFMF8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuc2lnbmtvcmVhLmNvbS9jcHMuaHRtbDAuBggrBgEFBQcCAjAiHiDHdAAgx3jJncEcACDC3NXYxqkAIMd4yZ3BHMeFssiy5DB1BgNVHREEbjBsoGoGCSqDGoyaRAoBAaBdMFsMFlNpZ25Lb3JlYV9NeURhdGFfVXNlcjIwQTA_BgoqgxqMmkQKAQEBMDEwCwYJYIZIAWUDBAIBoCIEIIekmuP0cdNt6Yh3vX10Sip4JBic-Oa8lv8hetbEzlUFMFYGA1UdHwRPME0wS6BJoEeGRWxkYXA6Ly8yMTEuMTc1LjgxLjEwMjo2ODkvb3U9ZHAxMXAxMyxvdT1BY2NyZWRpdGVkQ0Esbz1TaWduS29yZWEsYz1LUjA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6Ly8yMTEuMTc1LjgxLjEwMS9vY3NwLnBocDANBgkqhkiG9w0BAQsFAAOCAQEAtLa2VrCL8szfKUMbSke_jmRszuhYyV4pKky4SJcJ3alyPjBuupnrat7ePs1JyjbrkKgsOOTKxlWPIBH9jzRIa06pZS86V9C6ALS8YoLuRZ8QmG3BtB6n7Nqh5ZgwnUfbzpcQYZ5U1VLpsh_uGBVX2jCcpqnKEeAKPhsYsGWkCHHF5GV2H3UC7SfnQ0WFQGxvAtQSA8QQbQ3oC2j_2MlEW35kekRKC5svV_cRaZtkotNbeg_6JOu6Uk6xxqS829WZJy6RtzBOSMAbu5_F-WOV5OPjnVNML5GCbCrIplLgR7TOp8XNkhw_8HcDmL67YxcS8hXcn_dBhgDY8msISCRRgzGCAfIwggHuAgEBMFwwVTELMAkGA1UEBhMCS1IxEjAQBgNVBAoMCVNpZ25Lb3JlYTEVMBMGA1UECwwMQWNjcmVkaXRlZENBMRswGQYDVQQDDBJTaWduS29yZWEgVGVzdCBDQTUCAwhiaTANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDcxNjA0MTk1N1owLwYJKoZIhvcNAQkEMSIEIBomV21oI-p5M-KZjV64lNyNH8h6-e2Dgpx4AZwBKG7KMA0GCSqGSIb3DQEBAQUABIIBAFPkpNOEYYY8YCNh1iBaI-7Vtn7iLYVey9n1146v8hrd6pGd5zzO-acmK7JakRH6X5BAjPhgAhdfpYh_QjcRx83tF8_6tvL4Mb6vPPcx8AWx2ov-qQbjJEvHt3eJolbIbfRxUhoDZbpnzPgn_4bEcDKSlCLoE4AJiiQTtrwXrjRC7hs4Cx5QWs5mhze4pJVJaxHG5JMQBVBVAa_sgCaqsB1hCrc-QM08lFMDgPMpE5qAW7n0gBU_3clhpvQkDoNDyWYaVofqhInf_RXTc6V1g3soZYJIPlu-dpiMwkwmwHBztJKRCLighQhgGzjlo7JYBF-OAZkMzOKCyNN2N3L1E-I";
		consent_encoded = "MIIINAYJKoZIhvcNAQcCoIIIJTCCCCECAQExDzANBglghkgBZQMEAgEFADBXBgkqhkiG9w0BBwGgSgRIeyJjb25zZW50Ijoi6rOE7KKMIOygleuztC4uLiIsImNvbnNlbnROb25jZSI6Ik1USXpORFUyTnpnNU1ERXlNelExTmc9PSJ9oIIFujCCBbYwggSeoAMCAQICAwhiaTANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJLUjESMBAGA1UECgwJU2lnbktvcmVhMRUwEwYDVQQLDAxBY2NyZWRpdGVkQ0ExGzAZBgNVBAMMElNpZ25Lb3JlYSBUZXN0IENBNTAeFw0yMTA3MDgwODM0MDBaFw0yMjA3MDgxNDU5NTlaMIGQMQswCQYDVQQGEwJLUjESMBAGA1UECgwJU2lnbktvcmVhMRgwFgYDVQQLDA_thYzsiqTtirjsl4XsooUxGDAWBgNVBAsMD-2FjOyKpO2KuO2ajOyCrDEYMBYGA1UECwwP7YWM7Iqk7Yq47KeA7KCQMR8wHQYDVQQDDBZTaWduS29yZWFfTXlEYXRhX1VzZXIyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1d09Yl3_i2ULSVqtvJtkcJ4Hmgk6zbaeEDee3nTw2c4rFPDHiLKJnG41H7EtUoZR8Xbdfvor1FzZUZVAjJjCYpZ_AXEIL3FSXoQG2eI6D6j4Q0wVaoXZ-LAxDeFapw7jB3ycoc3FlGBDweECpQLe8zjq04hJ0xfO9QexJOi5rlKLwNnjMDXJuN8pLeLJX0a5VvV3XJ8f-k_8mZcYS6A_va4MYmzHafPx17xM8pmPZbO89ElqCwWaGciSswoq8vNDoKsHHgsdoxBRS_kfeYUAkpXRPnIXuRMX2UaA3SPZ_3wkcSWcXJ9CkMdoWj046UsruOUdz3L30YbEya07hZEUDQIDAQABo4ICUTCCAk0wgZMGA1UdIwSBizCBiIAU8XCpr2_PnYusgYXMFvR82YVcDMShbaRrMGkxCzAJBgNVBAYTAktSMQ0wCwYDVQQKDARLSVNBMS4wLAYDVQQLDCVLb3JlYSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBDZW50cmFsMRswGQYDVQQDDBJLaXNhIFRlc3QgUm9vdENBIDeCAQUwHQYDVR0OBBYEFH8xBP3cZFhIzn6n0bct8476pnmQMA4GA1UdDwEB_wQEAwIGwDB7BgNVHSABAf8EcTBvMG0GCiqDGoyaRAUBAQUwXzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5zaWdua29yZWEuY29tL2Nwcy5odG1sMC4GCCsGAQUFBwICMCIeIMd0ACDHeMmdwRwAIMLc1djGqQAgx3jJncEcx4WyyLLkMHUGA1UdEQRuMGygagYJKoMajJpECgEBoF0wWwwWU2lnbktvcmVhX015RGF0YV9Vc2VyMjBBMD8GCiqDGoyaRAoBAQEwMTALBglghkgBZQMEAgGgIgQgh6Sa4_Rx023piHe9fXRKKngkGJz45ryW_yF61sTOVQUwVgYDVR0fBE8wTTBLoEmgR4ZFbGRhcDovLzIxMS4xNzUuODEuMTAyOjY4OS9vdT1kcDExcDEzLG91PUFjY3JlZGl0ZWRDQSxvPVNpZ25Lb3JlYSxjPUtSMDoGCCsGAQUFBwEBBC4wLDAqBggrBgEFBQcwAYYeaHR0cDovLzIxMS4xNzUuODEuMTAxL29jc3AucGhwMA0GCSqGSIb3DQEBCwUAA4IBAQC0trZWsIvyzN8pQxtKR7-OZGzO6FjJXikqTLhIlwndqXI-MG66metq3t4-zUnKNuuQqCw45MrGVY8gEf2PNEhrTqllLzpX0LoAtLxigu5FnxCYbcG0Hqfs2qHlmDCdR9vOlxBhnlTVUumyH-4YFVfaMJymqcoR4Ao-GxiwZaQIccXkZXYfdQLtJ-dDRYVAbG8C1BIDxBBtDegLaP_YyURbfmR6REoLmy9X9xFpm2Si01t6D_ok67pSTrHGpLzb1ZknLpG3ME5IwBu7n8X5Y5Xk4-OdU0wvkYJsKsimUuBHtM6nxc2SHD_wdwOYvrtjFxLyFdyf90GGANjyawhIJFGDMYIB8jCCAe4CAQEwXDBVMQswCQYDVQQGEwJLUjESMBAGA1UECgwJU2lnbktvcmVhMRUwEwYDVQQLDAxBY2NyZWRpdGVkQ0ExGzAZBgNVBAMMElNpZ25Lb3JlYSBUZXN0IENBNQIDCGJpMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjEwNzE2MDQxOTU3WjAvBgkqhkiG9w0BCQQxIgQgss9mlgG9D3LqdSavhaKgWHyfKsam4WxCG_mo0PX4wsAwDQYJKoZIhvcNAQEBBQAEggEAP0cZDYvc-ezWHyj-wiyeyS7i16e2ZMCuvYGuVnPW8G2_ULbt4mMfe2qRndJ_vGqvr5qAqfi99jK6tS_1wT1uPUjOh6w0WVBN-nftlv5F2_ssacJr0NJjdRGl5hHRgHA5f_7V8DTkwicPX8QZr0Zx5fVWNmwpJxS7qGvZbmmWU1s-XIe3T2Rhb7O_0izLKA02p3WY7wPpyyHVckPfG0JhFFVu4VkU0NmwP_0rUqhKEA1rZq0wEqmQ2XbcwfoWQGe463sM9FAb6SgSLtYmpLAzGtnAlhNEFjc_Nq14Pg-MGToj6PeCuGFacy1y8lWNQ9hFo_5wXag5DMlK7kjEKjXSHw";
		person_encoded = nodeReq.getText("/signedDataList/0", "signedPersonInfoReq");
		consent_encoded = nodeReq.getText("/signedDataList/0", "signedConsent");
		ArrayNode arrays = nodeReq.getArrayNode("/signedDataList");
		System.out.println(">>>>> arrays.size = " + arrays.size());
		System.out.println(">>>>> person_encoded = " + person_encoded);
		System.out.println(">>>>> consent_encoded = " + consent_encoded);
		
		/* 1. url-decoding */
		byte[] signed_personInfoReq = VarUtils.base64_url_decoding(person_encoded);
		byte[] signed_consentInfo = VarUtils.base64_url_decoding(consent_encoded);

		/* 2. 검증 데몬에 인자값으로 넣기 위한 포맷의 서명 데이터 획득 */
		String personInfoForVerify = VarUtils.get_data_for_CMSVerify(person_encoded);
		String consentInfoForVerify = VarUtils.get_data_for_CMSVerify(consent_encoded);

		/* 3. 각 서명 데이터에서 인증서 byte 값 획득  */
		byte[] personCert = ClientUtils.get_certificate_from_cms(signed_personInfoReq);
		byte[] consentCert = ClientUtils.get_certificate_from_cms(signed_consentInfo);

		/*  4. 각 서명 데이터에서 nonce 값 획득 */
		String ucpidNonceInCms = ClientUtils.get_ucpidNonce_from_signedPersonInfoReq(signed_personInfoReq);
		String consentNonceInCms = ClientUtils.get_consentNonce_from_signdConsentInfo(signed_consentInfo);

		/* 5. 마이데이터 사업자로부터 전달 받은 nonce 값 저장 */
		//String ucpidNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 ucpidNonce 값";
		//String consentNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 consentNonce 값";

		/* 각 서명데이터의 서명시간(Date형) 획득 */
		Date SigningTimeUCPID = (Date) ClientUtils.getSigningTime(signed_personInfoReq);
		Date SigningTimeConset = (Date) ClientUtils.getSigningTime(signed_consentInfo);

		/* 각 서명데이터의 서명시간(String형) 획득 */
		String SigningTimeUCPID_STR = ClientUtils.getSigningTime_str(signed_personInfoReq);
		String SigningTimeConset_STR = ClientUtils.getSigningTime_str(signed_consentInfo);

		//if(ucpidNonceInCms.equals(ucpidNonceInApi) && consentNonceInCms.equals(consentNonceInApi)){ /* Nonce 값이 동일할 경우 (재전송 공격 방지) */
		{
					//if(isSameCertificate(personCert,consentCert)){ /* 두 서명 데이터에서 사용된 인증서가 동일할 경우 <- 해당 인증서 비교 함수는 정보제공자가 개발필요 */
				{
					/*
					 * 위의 personInfoForVerify, consentInfoForVerify 값을 검증데몬 혹은 검증라이브러리에 파라미터값으로 넣어 서명 검증 실시.
						personInfoForVerify - 검증
						consentInfoForVerify(전송요구내역) - 검증 후 원문확인
					 */
					//if(isVerifyingOk()){/* 검증데몬에서 서명데이터의 검증이 정상적으로 성공하였을 경우 */
					{

						VarUtils.setPropertiesPath("./config/route.properties");/*properties 파일 설정(절대 경로 혹은 상대경로)*/

						//String ucpidNonce = "정보제공자가 직접생성한 ucpidNonce";
						//String ucpidNonce = ucpidNonceInCms;
						String ucpidNonce = StringTools.getNonce();
						ucpidNonce = Base64.encodeBase64URLSafeString(ucpidNonce.getBytes());
						
						//String cpCode ="정보제공자 cpCode (한국정보인증에 신청)"; // Test cpCode C0123456789A(ispurl www.mydata.co.kr)
						String cpCode = "C0123456789A"; // Test cpCode C0123456789A(ispurl www.mydata.co.kr)
						//String cpRequestNumber = "마이데이터사업자로부터 받은 tx_id 값";
						String cpRequestNumber = "12345";
						//String ca_code ="마이데이터사업자로부터 받은 인증기관 기관코드"; // SignKorea / yessign / KICA / CrossCert
						String ca_code = "SignKorea";

						try{
							String signCertPath = VarUtils.getResourceFromProperty("signCert");
							byte[] certificate = VarUtils.getFromFile(signCertPath);
							VarUtils.setCertPassword("11223344");	//서버인증서 비밀번호

							String serverIp = "";
							int serverPort = 0;

							if("SignKorea".equals(ca_code)){
								serverIp = "211.175.81.101";
								serverPort = 8098;
							}
							else if("yessign".equals(ca_code)){
								serverIp = "203.233.91.231";
								serverPort = 4719;
							}
							else if("KICA".equals(ca_code)){
								serverIp = "121.254.188.161";
								serverPort = 9090;
							}
							else if("CrossCert".equals(ca_code)){
								serverIp = "203.248.34.63";
								serverPort = 17586;
							}
							
							/* UCPID 서버로 보내기 위한 메시지 생성*/
							byte[] UCPIDRequest = RequestUtils.getUCPIDRequest(ucpidNonce, cpCode, cpRequestNumber, certificate, signed_personInfoReq, 1);
							/* UCPID 서버로 UCPIDRequest Message 전송 및 UCPIDResponse 획득 */
							byte[] bUCPIDResponse = request2UCPID(UCPIDRequest, serverIp, serverPort);

							String status = ResponseUtils.getStatusCode(bUCPIDResponse);
							if ("OK".equals(status)){
								UCPIDResponse ucpidResponse = ResponseUtils.getInstance(bUCPIDResponse);

								int version = ucpidResponse.getVersion();
								String UCPIDNonce = ucpidResponse.getUcpidNonce();
								String CpRequestNumber = ucpidResponse.getCpRequestNumber();
								String certDn = ucpidResponse.getCertDn();
								String CpCode = ucpidResponse.getCpCode();
								String di = ucpidResponse.getDi();
								String realName = ucpidResponse.getRealName();
								int gender = ucpidResponse.getGender();
								int nationalInfo = ucpidResponse.getNationalInfo();
								String birthDate = ucpidResponse.getBirthDate();
								/*
									ciupdate가 홀수일경우 ci이용 짝수일경우 ci2이용
									ex) ciupdate=1 ci이용
										ciupdate=2 ci2이용
										ciupdate=3 ci이용
										ciupdate=4 ci2이용
										       .
											   .
								*/
								int ciupdate = ucpidResponse.getCiUpdate();
								String ci = ucpidResponse.getCi();
								String ci2 = ucpidResponse.getCi2();

								System.out.println("personInfo's version ==============> " + version);
								System.out.println("personInfo's UCPIDNonce ===========> " + UCPIDNonce);
								System.out.println("personInfo's cpRequestNumber ======> " + CpRequestNumber);
								System.out.println("personInfo's certDn ===============> "+ certDn);
								System.out.println("personInfo's cpCode ===============> " + CpCode);
								System.out.println("personInfo's Di ===================> " + di);
								System.out.println("personInfo's realName =============> " + realName);
								System.out.println("personInfo's gender ===============> " + gender);
								System.out.println("personInfo's nationalInfo =========> " + nationalInfo);
								System.out.println("personInfo's birthDate ============> " + birthDate);
								System.out.println("personInfo's ciupdate =============> " + ciupdate);
								System.out.println("personInfo's ci ===================> " + ci);
								System.out.println("personInfo's ci2 ==================> " + ci2);
								
								mapRes.put("version", version);
								mapRes.put("UCPIDNonce", UCPIDNonce);
								mapRes.put("CpRequestNumber", CpRequestNumber);
								mapRes.put("certDn", certDn);
								mapRes.put("CpCode", CpCode);
								mapRes.put("di", di);
								mapRes.put("realName", realName);
								mapRes.put("gender", gender);
								mapRes.put("nationalInfo", nationalInfo);
								mapRes.put("birthDate", birthDate);
								mapRes.put("ciupdate", ciupdate);
								mapRes.put("ci", ci);
								mapRes.put("ci2", ci2);
							}
							else{
								System.out.println("your UCPIDResponse is invalid. your error code is \"" + status + "\"");
							}
						}catch(MydataException e){
							/**
							 *
								서명데이터(UCPIDRequest)가 잘못된경우로 동일로직으로 처리하여도 무관함
								PARAMETER_EMPTY_IN_FUNCTION  / ERROR_IN_BYTE_TO_SEQUENCE / EMPTY_RETURN_VALUE_FROM_FUNCTION / INVALID_STRUCTURE
							 */
							if(ErrorCode.PARAMETER_EMPTY_IN_FUNCTION == e.getErrCode()){
								// 함수에 인자값이 null일 경우
								System.out.println("PARAMETER_EMPTY_IN_FUNCTION");
							}else if(ErrorCode.ERROR_IN_BYTE_TO_SEQUENCE == e.getErrCode()){
								// byte 값을 sequence로 변환실패
								System.out.println("ERROR_IN_BYTE_TO_SEQUENCE");
							}else if(ErrorCode.EMPTY_RETURN_VALUE_FROM_FUNCTION == e.getErrCode()){
								// 함수로부터 리턴받은 값이 null일 경우
								System.out.println("EMPTY_RETURN_VALUE_FROM_FUNCTION");
							}else if(ErrorCode.INVALID_STRUCTURE == e.getErrCode()){
								// 서명데이터의 asn.1 구조가 잘못된 경우
								System.out.println("INVALID_STRUCTURE");
							}else if(ErrorCode.NOT_INVALID_VALUE == e.getErrCode()){
								// UCPID Version이 다른경우 (version 2)
								System.out.println("NOT_INVALID_VALUE");
							}else if(ErrorCode.EMPTY_VALUE_IN_PROPERTIES == e.getErrCode()){
								//route.properties의 변수명이 다를경우
								System.out.println("EMPTY_VALUE_IN_PROPERTIES");
							}
							System.out.println(">> " + e.getMessage() + ", " + e.getErrCode());
						}catch(Exception e){
							e.printStackTrace();
						}
					}
					//else{
					//	System.out.println("CMS Verify not ok");
					//}
				}
				//else{
				//	System.out.println("isSameCertificate not ok");
				//}
		}
		//else{
		//	System.out.println("Nonce not ok");
		//}

		return mapRes;
	}
}
