package org.tain.version.ver20211126;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Date;

import SK.Exception.MydataException;
import SK.Utility.UCPIDResponse;
import SK.Utils.ClientUtils;
import SK.Utils.RequestUtils;
import SK.Utils.ResponseUtils;
import SK.Utils.VarUtils;


public class Test {

	public static void main(String[] args) {
		
		try{
			
			String person_encoded = "마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_personInfoReq의 url-encoding된 값";
			String consent_encoded = "마이데이터사업자로부터 통합인증 api-002를 통해 전달 받은 signed_consentInfo의 url-encoding된 값";

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
			String ucpidNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 ucpidNonce 값";
			String consentNonceInApi = "마이데이터사업자로부터 통합인증 api -002를 통해 전달 받은 consentNonce 값";
			
			/* 각 서명데이터의 서명시간(Date형) 획득 */
			Date SigningTimeUCPID = ClientUtils.getSigningTime(signed_personInfoReq);
			Date SigningTimeConset = ClientUtils.getSigningTime(signed_consentInfo);

			/* 각 서명데이터의 서명시간(String형) 획득 */		
			String SigningTimeUCPID_STR = ClientUtils.getSigningTime_str(signed_personInfoReq);
			String SigningTimeConset_STR = ClientUtils.getSigningTime_str(signed_consentInfo);
				
			if(ucpidNonceInCms.equals(ucpidNonceInApi) && consentNonceInCms.equals(consentNonceInApi)){ /* Nonce 값이 동일할 경우 (재전송 공격 방지) */
					
				//if(isSameCertificate(personCert,consentCert)){ /* 두 서명 데이터에서 사용된 인증서가 동일할 경우 <- 해당 인증서 비교 함수는 정보제공자가 개발필요 */
				if (Boolean.TRUE){
					
					/*
					 * 위의 personInfoForVerify, consentInfoForVerify 값을 검증데몬 혹은 검증라이브러리에 파라미터값으로 넣어 서명 검증 실시.
						personInfoForVerify - 검증
						consentInfoForVerify(전송요구내역) - 검증 후 원문확인
					 */						
					//if(isVerifyingOk()){/* 검증데몬에서 서명데이터의 검증이 정상적으로 성공하였을 경우의 가상함수 */
					if (Boolean.TRUE) {
						
						VarUtils.setPropertiesPath("config_data/route.properties");/*properties 파일 설정(절대 경로 혹은 상대경로)*/
						
						String ucpidNonce = "정보제공자가 직접생성한 ucpidNonce";
						String cpCode ="C0123456789A"; //정보제공자 cpCode (한국정보인증에 신청),  Test cpCode C0123456789A(ispurl www.mydata.co.kr)
						String cpRequestNumber = "MD_ZWAACP0000_ZWAACP0000_0000000000_ZXAACP0000_YYYYMMDDHHMMSS_000000000001";  //테스트데이터입니다.  (마이데이터사업자로부터 받은 tx_id 값)
						String ca_code ="마이데이터사업자로부터 받은 인증기관 기관코드"; // SignKorea / yessign / KICA / CrossCert

							
						String signCertPath = VarUtils.getResourceFromProperty("signCert");
						byte[] certificate = VarUtils.getFromFile(signCertPath);	
						VarUtils.setCertPassword("1q2w3e4r!!");	//서버인증서 비밀번호 (SignKorea_MyData_Server 인증서 비밀번호)
								
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
						if("OK".equals(status)){
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
					
						}
						else{
							System.out.println("your UCPIDResponse is invalid. your error code is \"" + status + "\"");
						}	
					}
					else{
						System.out.println("CMS Verify not ok");
					}
				}
				else{
					System.out.println("isSameCertificate not ok");
				}
			}
			else{
				System.out.println("Nonce not ok");
			}
		}catch(MydataException e){
			//System.out.println("Error ==> [" + e.getErrCode()+"]"+ e.getErrMessage());		
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public static byte[] request2UCPID(byte[] UCPIDRequest,String serverIp, int serverPort){
		
		Socket socket = null;
		DataInputStream reader = null;
		DataOutputStream writer = null;
		byte[] UCPIDResponse = null;
		
		try{
			socket = new Socket(serverIp,serverPort);
			if(socket !=null){
				if(socket.isConnected()){
					writer = new DataOutputStream(socket.getOutputStream());
					reader = new DataInputStream(socket.getInputStream());
					
					if(writer !=null && reader != null){
						writer.writeInt(UCPIDRequest.length);
						writer.write(UCPIDRequest,0,UCPIDRequest.length);
						writer.flush();
						
						int readInt = reader.readInt();
						UCPIDResponse = new byte[readInt];
						reader.readFully(UCPIDResponse);
					}
				}
			}
		}catch(IOException e){
			e.printStackTrace();
		}finally{
			try{
				if(socket != null) socket.close();
				if(writer != null) writer.close();
				if(reader != null) reader.close();
			}catch(IOException e){
				e.printStackTrace();
			}
		}
		return UCPIDResponse;
	}
	
}
