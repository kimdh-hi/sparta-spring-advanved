package com.sparta.selectshop.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Setter
@Getter // get 함수를 일괄적으로 만들어줍니다.
@NoArgsConstructor // 기본 생성자를 만들어줍니다.
@Entity // DB 테이블 역할을 합니다.
public class UserTime {
    // ID가 자동으로 생성 및 증가합니다.
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Id
    private Long id;

    @OneToOne
    @JoinColumn(nullable = false)
    private User user;

    @Column(nullable = false, columnDefinition = "bigint default 0")
    private int totalCount;

    @Column(nullable = false)
    private long totalTime;

    public UserTime(User user, long totalTime, int totalCount) {
        this.user = user;
        this.totalTime = totalTime;
        this.totalCount = totalCount;
    }

    public void updateTotalTimeAndCallCount(long totalTime, int totalCount) {
        this.totalTime = totalTime;
        this.totalCount = totalCount;
    }
}