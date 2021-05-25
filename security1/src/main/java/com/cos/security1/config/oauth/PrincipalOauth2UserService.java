package com.cos.security1.config.oauth;


import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2Userinfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;


    //구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)throws OAuth2AuthenticationException{
        //System.out.println("userRequest:"+userRequest);

        OAuth2User oauth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 ->code를 리턴(OAuth-Client 라이브러리)->AcessToken요청
        //userRequest 정보 -> loadUser함수 호출 ->구글로부터 회원프로필 받아준다.



        //회원가입을 강제로 진행해볼 예정
        OAuth2Userinfo oAuth2Userinfo =null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2Userinfo= new GoogleUserInfo(oauth2User.getAttributes());

        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2Userinfo= new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
        }
        System.out.println(oAuth2Userinfo);

        String provider = oAuth2Userinfo.getProvider();
        String providerId= oAuth2Userinfo.getProviderId();
        String username=provider+"_"+providerId;//google_xxxx
        String password =bCryptPasswordEncoder.encode("승민");
        String email= oAuth2Userinfo.getEmail();
        String role ="ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity==null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
