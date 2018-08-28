package com.repl.kakaoservice;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

@Configuration
@EnableOAuth2Client
@Controller
public class KakaoController {

//    @Autowired
//    private OAuth2ClientContext oauth2Context;

    @Bean
    public OAuth2RestTemplate getOAuth2RestTemplate() {
        AccessTokenRequest atr = new DefaultAccessTokenRequest();
        return new OAuth2RestTemplate(resource(), new DefaultOAuth2ClientContext(atr));
    }

    private final String publicKey = "input your publicKey";
    private final String adminKey = "input your adminKey";
//    private final String uri = "https://kauth.kakao.com/oauth/authorize?client_id=1d6424c5ede35360104614fe6fb6d405&redirect_uri=http://localhost:8080/callback&response_type=code";
    private final String firstUrl = "https://kauth.kakao.com/oauth/authorize";
    private final String secondUrl = "https://kauth.kakao.com/oauth/token";
    private final String logoutUrl = "https://kapi.kakao.com/v1/user/logout";
    private final String appConnectUrl = "https://kapi.kakao.com/v1/user/signup";
    private final String confirmUrl = "https://kapi.kakao.com/v2/user/me";
    private final String listRequestUrl = "https://kapi.kakao.com/v1/user/ids";
    private final String profileRequestUrl = "https://kapi.kakao.com/v1/api/talk/profile";

    private String stateCode = null;
    private String cookieValue = null;

    @GetMapping("/login")
    public void login() {

    }

    @RequestMapping("/start")
    public String start(HttpServletRequest request, HttpServletResponse response) {
        OAuth2RestTemplate restTemplate = getOAuth2RestTemplate();

        //방법 3) header에 Authorization을 지워준다.(csrf 해결 못함)
//        HttpHeaders requestHeaders = new HttpHeaders();
//        requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
////        requestHeaders.set("Authorization", "");
//        requestHeaders.set("X-CSRF-TOKEN", stateCode);
//
//        HttpEntity<String> req = new HttpEntity<String>(requestHeaders);
//
//        ResponseEntity<String> response = restTemplate.exchange(firstUrl, HttpMethod.GET, req, String.class);

//        Cookie[] cookies = request.getCookies();
//
//        for(int i=0;i<cookies.length;i++) {
//            cookies[i].setMaxAge(0);
//            cookies[i].setPath("/");
//            response.addCookie(cookies[i]);
//        }
        //방법 1)
        ResponseEntity<String> responseResult = restTemplate.getForEntity(firstUrl, String.class);

        //방법 2) - 그러나 csrf 문제는 해결 못함
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//        headers.set("state", stateCode);
//
//        HttpEntity<String> request = new HttpEntity<String>(headers);
//
//        ResponseEntity<String> response = restTemplate.exchange(firstUrl, HttpMethod.GET, request, String.class);
        return null;
    }

    private OAuth2ProtectedResourceDetails resource() {
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails = new AuthorizationCodeResourceDetails();
        authorizationCodeResourceDetails.setClientId(publicKey);
        authorizationCodeResourceDetails.setUserAuthorizationUri("https://kauth.kakao.com/oauth/authorize");
        authorizationCodeResourceDetails.setAccessTokenUri("https://kauth.kakao.com/oauth/token");
        authorizationCodeResourceDetails.setPreEstablishedRedirectUri("http://localhost:8080/callback");
        authorizationCodeResourceDetails.setGrantType("authorization_code");
        authorizationCodeResourceDetails.setUseCurrentUri(false);

        return authorizationCodeResourceDetails;
    }

    @RequestMapping(value="/callback", produces="application/json", method={RequestMethod.GET, RequestMethod.POST})
    public String callback(@RequestParam("code") String code, @RequestParam("state") String state, HttpServletResponse response) {
        System.out.println(">>>code: " + code);
        stateCode=state;
//        OAuth2RestTemplate restTemplate = getOAuth2RestTemplate();
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        HttpEntity<String> request = new HttpEntity<String>(headers);

//        List<NameValuePair> postParams = new ArrayList<NameValuePair>();
//        postParams.add(new BasicNameValuePair("grant_type", "authorization_code"));
//        postParams.add(new BasicNameValuePair("client_id", "1d6424c5ede35360104614fe6fb6d405"));
//        postParams.add(new BasicNameValuePair("redirect_uri", "http://localhost:8080/callback"));
//        postParams.add(new BasicNameValuePair("code", code));

        String url = "https://kauth.kakao.com/oauth/token";
        url += "?code=" + code;
        url += "&grant_type=authorization_code";
        url += "&redirect_uri=http://localhost:8080/callback";
        url += "&client_id=1d6424c5ede35360104614fe6fb6d405";

        AccessInfo obj = restTemplate.postForObject(url, request, AccessInfo.class);
        String accessToken = obj.getAccess_token();
        System.out.println(">>>obj: " + obj);
        System.out.println(">>>accessToken: " + accessToken);
        Cookie cookie = new Cookie("Authorization", accessToken);
        cookie.setComment("kakao-access-token");
        cookie.setMaxAge(60*60*24);
        cookie.setPath("/");
        response.addCookie(cookie);
        cookieValue=accessToken;

        return "login";
    }


    @RequestMapping(value="/logouts", produces={"application/json", "application/x-www-form-urlencoded"}, method={RequestMethod.GET, RequestMethod.POST})
    public String logouts(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("logout 컨트롤러 진입");
        // 쿠키 가져오기
//        String authCookie = null;
//        int cookieInx = 0;
        RestTemplate restTemplate = new RestTemplate();
//
//        Cookie[] cookies = request.getCookies();
//        if(cookies!=null) {
//        for(Cookie cookie:cookies) {
//            if ("Authorization".equals(cookie.getName())) {
//                authCookie = cookie.getValue();
//                cookieInx = cookieInx;
//                System.out.println(">>>authCookieValue: " + authCookie + "cookieInx" + cookieInx);
//                break;
//            }
//            cookieInx++;
//            }
//        }

        // 헤더에 정보 넣기(base64로 바꿀 필요 없음)
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        requestHeaders.setContentType(MediaType.APPLICATION_JSON);
        requestHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        requestHeaders.set("Authorization", "Bearer " + cookieValue);
        System.out.println("cookieValue: " + cookieValue);

        HttpEntity<String> req = new HttpEntity<String>(requestHeaders);

        ResponseEntity<Object> logoutResult = restTemplate.exchange(logoutUrl, HttpMethod.POST, req, Object.class);
        System.out.println(">>>logoutResult" + logoutResult.toString());
        System.out.println(">>>response" + response.toString());
//        if(logoutResult.getStatusCodeValue()==200) {
//            cookies[cookieInx].setMaxAge(0);
//            cookies[cookieInx].setPath("/");
//            response.addCookie(cookies[cookieInx]);
//        }

        return "login";

    }

    @RequestMapping(value="/connect", produces={"application/json", "application/x-www-form-urlencoded"}, method={RequestMethod.GET, RequestMethod.POST})
    public String connect(HttpServletRequest request) {

//        String authCookie = null;
//        int cookieInx = 0;

        // 둘 다 가능
        // OAuth2RestTemplate restTemplate = getOAuth2RestTemplate();
        RestTemplate restTemplate = new RestTemplate();


//
//        Cookie[] cookies = request.getCookies();
//        if(cookies!=null) {
//            for(Cookie cookie:cookies) {
//                if ("Authorization".equals(cookie.getName())) {
//                    authCookie = cookie.getValue();
//                    cookieInx = cookieInx;
//                    System.out.println(">>>authCookieValue: " + authCookie + "cookieInx" + cookieInx);
//                    break;
//                }
//                cookieInx++;
//            }
//        }

        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        requestHeaders.setContentType(MediaType.APPLICATION_JSON);
        requestHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        requestHeaders.set("Authorization", "KakaoAK " + adminKey);

        HttpEntity<String> req = new HttpEntity<String>(requestHeaders);

        ResponseEntity<Object> connectResult = restTemplate.exchange(listRequestUrl, HttpMethod.GET, req, Object.class);
        System.out.println(">>>connectResult: " + connectResult.toString());

        return "login";
    }

    @RequestMapping(value="/profile", produces={"application/json", "application/x-www-form-urlencoded"}, method={RequestMethod.GET, RequestMethod.POST})
    public String profile(HttpServletRequest request) {

//        String authCookie = null;
//        int cookieInx = 0;

        // 둘 다 가능
        // OAuth2RestTemplate restTemplate = getOAuth2RestTemplate();
        RestTemplate restTemplate = new RestTemplate();


//
//        Cookie[] cookies = request.getCookies();
//        if(cookies!=null) {
//            for(Cookie cookie:cookies) {
//                if ("Authorization".equals(cookie.getName())) {
//                    authCookie = cookie.getValue();
//                    cookieInx = cookieInx;
//                    System.out.println(">>>authCookieValue: " + authCookie + "cookieInx" + cookieInx);
//                    break;
//                }
//                cookieInx++;
//            }
//        }

        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        requestHeaders.setContentType(MediaType.APPLICATION_JSON);
        requestHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        requestHeaders.set("Authorization", "Bearer " + cookieValue);

        HttpEntity<String> req = new HttpEntity<String>(requestHeaders);

        ResponseEntity<Object> connectResult = restTemplate.exchange(profileRequestUrl, HttpMethod.GET, req, Object.class);
        System.out.println(">>>connectResult: " + connectResult.toString());

        return "login";
    }



//    @GetMapping("/start")
//    public String start() {
//
//        try {
//
//            URL obj = new URL(uri);
//            HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
//
//            conn.setRequestProperty("Content-Type", "application/json");
//            conn.setDoOutput(true);
//
//            conn.setRequestMethod("GET");
//
////            conn.setRequestProperty("X-*****-Client-Id", ClientId); //header 에 값 셋팅
////            conn.setRequestProperty("X-*****-Client-Secret", ClientSecret); //header 에 값 셋팅
//
//            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(),"UTF-8"));
//
//            String inputLine;
//            StringBuffer response = new StringBuffer();
//
//            while ((inputLine = in.readLine()) != null) {
//                response.append(inputLine);
//            }
//            in.close();
//
//            System.out.println(">>>response: " + response.toString()); //결과, json결과를 parser하여 처리
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return null;
//    }

}
