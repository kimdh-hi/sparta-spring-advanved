package com.sparta.selectshop.aop;

import com.sparta.selectshop.domain.User;
import com.sparta.selectshop.domain.UserTime;
import com.sparta.selectshop.repository.UserTimeRepository;
import com.sparta.selectshop.security.UserDetailsImpl;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component // 스프링 IoC 에 빈으로 등록
@Aspect
public class UserTimeAop {
    private final UserTimeRepository userTimeRepository;

    public UserTimeAop(UserTimeRepository userTimeRepository) {
        this.userTimeRepository = userTimeRepository;
    }

    // controller 패키지 이하 모든 public 메서드에 적용
    @Around("execution(public * com.sparta.selectshop.controller..*(..))")
    public Object execute(ProceedingJoinPoint joinPoint) throws Throwable {
        // 측정 시작 시간
        long startTime = System.currentTimeMillis();

        try {
            // 핵심기능 수행
            Object output = joinPoint.proceed();
            return output;
        } finally {
            // 측정 종료 시간
            long endTime = System.currentTimeMillis();
            // 수행시간 = 종료 시간 - 시작 시간
            long runTime = endTime - startTime;
            // 로그인 회원이 없는 경우, 수행시간 기록하지 않음
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal().getClass() == UserDetailsImpl.class) {
                // 로그인 회원 -> loginUser 변수
                UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
                User loginUser = userDetails.getUser();

                // 수행시간 및 DB 에 기록
                UserTime userTime = userTimeRepository.findByUser(loginUser);
                if (userTime != null) {

                    int callCount = userTime.getCallCount();
                    callCount++;
                    // 로그인 회원의 기록이 있으면
                    long totalTime = userTime.getTotalTime();
                    totalTime = totalTime + runTime;
                    userTime.updateTotalTimeAndCallCount(totalTime, callCount);
                } else {
                    // 로그인 회원의 기록이 없으면
                    userTime = new UserTime(loginUser, runTime, 1);
                }

                System.out.println("[User Time] User: " + userTime.getUser().getUsername() + ", Total Time: " + userTime.getTotalTime() + " ms");
                userTimeRepository.save(userTime);
            }
        }
    }
}