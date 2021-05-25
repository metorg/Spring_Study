package com.cos.security1.config.oauth;


import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

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

        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 ->code를 리턴(OAuth-Client 라이브러리)->AcessToken요청
        //userRequest 정보 -> loadUser함수 호출 ->구글로부터 회원프로필 받아준다.

        OAuth2User oauth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getClientId();//google
        String providerId= oauth2User.getAttribute("sub");
        String username=provider+"_"+providerId;//google_xxxx
        String password =bCryptPasswordEncoder.encode("승민");
        String email= oauth2User.getAttribute("email");
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
        }
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
