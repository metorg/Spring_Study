package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
//login 요청해서 username,password 전송하면 (post)
//UsernamePasswordAuthenticationFilter 동작을함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter:로그인 시도중");

        //1. username,password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input=null;
//            while((input = br.readLine())!=null){
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken=
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
           //PrincipalDetailsService의 loadUserByUsernmae()함수가 실행됨
            //db에 있는 username과 password가 일치한다.


            Authentication authentication=
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session 영역에 저장됨.=>로그인이 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getPassword());
            //굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리 때문에 session에 넣어 준다
        return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행되요.
    //jwt 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨:인증이 완료되었다는 뜻임");
        PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

        //RSA방식은 아니구 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))//토큰 만료시간
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));//이게 시크릿 키

        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
