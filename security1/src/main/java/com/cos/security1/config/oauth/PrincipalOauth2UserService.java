package com.cos.security1.config.oauth;


import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)throws OAuth2AuthenticationException{
        System.out.println("userRequest:"+userRequest);

        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 ->code를 리턴(OAuth-Client 라이브러리)->AcessToken요청
        //userRequest 정보 -> loadUser함수 호출 ->구글로부터 회원프로필 받아준다.

        OAuth2User oauth2User = super.loadUser(userRequest);

        return super.loadUser(userRequest);

    }
}
