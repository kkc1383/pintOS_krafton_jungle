/* threads/fixed-points.h */
#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* 17.14 고정소수점 형식
 * 32비트 정수를 사용하여 실수 표현
 * 상위 17비트 : 정수부
 * 하위 14비트 : 소수부
 */

typedef int fixed_t; /* fixed-point를 표현하는 타입 */

/* fixed-point 1.0을 나타냄 */
#define F (1 << 14)

/* 변환 함수들 */

/* 정수 n을 fixed-point로 변환 */
#define INT_TO_FP(n) ((n)*F)

/* fixed-point x를 정수로 변환 (0과 가까워지는 변환) */
// 2.5 => 2, -2.5 => -2
#define FP_TO_INT_ZERO(x) ((x) / F)

/* fixed-point x를 정수로 변환 (절댓값 반올림) */
// 2.5 => 3 , -2.5 => -2
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? (((x) + F / 2) / F) : (((x)-F / 2) / F))

/* 사칙연산 */

/* fixed-point x + fixed-point y */
#define ADD_FP(x, y) ((x) + (y))

/* fixed-point x - fixed-point y */
#define SUB_FP(x, y) ((x) - (y))

/* fixed-point x + integer n */
// n을 고정소수점화 시키고 계산
#define ADD_FP_INT(x, n) ((x) + (n)*F)

/* fixed-point x - integer n */
#define SUB_FP_INT(x, n) ((x) - (n)*F)

/* fixed-point x * fixed-point y */
#define MULT_FP(x, y) (((int64_t)(x) * (y) / F))

/* fixed-point * integer n */
#define MULT_FP_INT(x, n) ((x) * (n))

/* fixed-point x / fixed-point y */
// result = (real_x * F / real_y * F) * F = (x / y) * F = (x * F / y)
// 말로하자면 결과도 소숫점으로 나올테니까 FP 형태로 하려고 F를 곱해주는건데 그걸 걍 x에다가 해버린 것 (곱셈의 교환법칙)
#define DIV_FP(x, y) (((int64_t)(x)) * F / (y))

/* fixed-point x / integer n */
#define DIV_FP_INT(x, n) ((x) / (n))

/* 59/60 */
#define FP_59_60 (DIV_FP_INT(INT_TO_FP(59), 60))

/* 1/60 */
#define FP_1_60 (DIV_FP_INT(INT_TO_FP(1), 60))

#endif /* threads/fixed-point.h */