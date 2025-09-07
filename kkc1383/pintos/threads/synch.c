/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"

#include <stdio.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value) {
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void sema_down(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  while (sema->value == 0) {  // sema_up에서 최댓값을 가져오므로 넣을때는 끝에서부터 걍 넣자
    list_push_back(&sema->waiters, &thread_current()->elem);

    thread_block();
  }
  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  sema->value++;
  if (!list_empty(&sema->waiters)) {
    // sema->waiters 중에서 우선순위 최댓값인거 가져와야 함. 비교함수가 반대여서 min을 씀...(최댓값뽑는게맞음)
    struct list_elem *max_elem = list_min(&sema->waiters, thread_priority_less, NULL);
    struct thread *t = list_entry(max_elem, struct thread, elem);
    list_remove(max_elem);  // 삭제까지 해줘야함 원래 pop이었으니까
    thread_unblock(t);
  }
  intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  sema_init(&lock->semaphore, 1);
}

static void donate_priority_dfs(struct thread *holder, int prioirty);
/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock *lock) {  // P 함수의 wrapper, 해당 락을 점유하고있는 holder를 찾아가 donate
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));

  enum intr_level old_level = intr_disable();
  struct thread *curr = thread_current();

  // priority donate nested
  if (lock->holder != NULL) {
    donate_priority_dfs(lock->holder, curr->priority);  // 해당 lock의 holder부터 시작해서 dfs로 우선순위 donate
  }

  curr->waiting_for_lock = lock;  //쓰레드 waiting_for_lock 필드 갱신

  intr_set_level(old_level);
  sema_down(&lock->semaphore);  // 여기서 block 당함

  /* 락 획득 후 처리 */
  old_level = intr_disable();     // 인터럽트 끄기(전역 데이터를 수정하기 때문에)
  curr->waiting_for_lock = NULL;  // 이젠 이 락에 대해선 안 기다리니까
  lock->holder = curr;            // 만약 뚫었다면 현재 스레드가 이 lock의 holder임
  curr->is_donated += 1;          // 내가 락을 소유하게 되었으니 is_donated 추가
  list_push_back(&curr->acquired_locks, &lock->holder_elem);  // 보유중인 락에 추가 이건 순서 상관없음
  intr_set_level(old_level);                                  // 인터럽트 복원
}
static void donate_priority_dfs(struct thread *holder, int prioirty) {
  int depth = 0;
  const int MAX_DEPTH = 8;

  struct thread *curr = holder;  // 첫 시작은 해당 락의 holder 부터

  // struct thread* visited[MAX_DEPTH]; // 여태 방문한 thread를 저장
  // int visited_count=0; //방문 횟수
  while (curr != NULL && depth < MAX_DEPTH) {
    // visited 배열을 순회하면서 현재 들어와 있는 쓰레드가 혹시 이미 방문했다면 false 반환
    // for(int i=0;i<visited_count;i++)
    //   if(visited[i]==curr) return false; // 순환발견, donation 중단

    if (curr->priority >= prioirty)  //우선순위가 이미 높거나 같다면
      break;                         //중단

    // priority donation 수행
    curr->priority = prioirty;

    // ready_list에 있다면 재정렬
    if (curr->status == THREAD_READY) {
      list_remove(&curr->elem);
      list_insert_ordered(get_ready_list(), &curr->elem, thread_priority_less, NULL);
    }

    // 다음 체인 확인 : 이 스레드가 다른 락을 기다리고 있는가
    if (curr->waiting_for_lock == NULL) {  // 다른 락을 기다리고 있지 않다면
      break;                               // 중단
    }

    //다른 락을 기다리고 있다면 다음 holder로 이동
    curr = curr->waiting_for_lock->holder;
    depth++;
  }
}
/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success) lock->holder = thread_current();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock) {  // V함수의 wrapper
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));

  enum intr_level old_level = intr_disable();
  struct thread *curr = thread_current();

  //현재 쓰레드의 acquired locks에서 노드 제거
  list_remove(&lock->holder_elem);

  // 우선순위 복구 내가 가지고 있는 acquire lock 중에서 가장 큰 걸로 받아와야함
  int new_priority = curr->original_priority;

  struct list_elem *e;  // acquired locks를 순회하면서 각각의 락
  // 현재 스레드가 보유중인 락을 순회 하면서 각 락의 우선순위 최댓값을 new_priority로 함(물론 내 original이 높다면
  // 그걸로 채택)
  for (e = list_begin(&curr->acquired_locks); e != list_end(&curr->acquired_locks); e = list_next(e)) {
    struct lock *other_lock = list_entry(e, struct lock, holder_elem);

    if (list_empty(&other_lock->semaphore.waiters)) continue;  // 대기자가 없는 락은 pass

    struct thread *front_thread = list_entry(list_front(&other_lock->semaphore.waiters), struct thread, elem);

    if (front_thread->priority > new_priority)  // 각 락의 우선순위 최댓값을 가지고 new_priority 갱신
      new_priority = front_thread->priority;
  }
  curr->priority = new_priority;  // 현재 스레드의 적절한 priority로 갱신
  curr->is_donated -= 1;          // 내가 풀었으니까 is_donated 하나 내리기

  lock->holder = NULL;
  sema_up(&lock->semaphore);  // 자원 1 공급해주고 waiter 중 우선순위 높은 쓰레드 unblock
  intr_set_level(old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  sema_init(&waiter.semaphore, 0);
  list_push_back(&cond->waiters, &waiter.elem);
  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters)) {
    struct list_elem *max_elem = NULL;
    int max_priority = -1;

    // for문으로 가장 높은 우선순위 찾기
    struct list_elem *e;
    for (e = list_begin(&cond->waiters); e != list_end(&cond->waiters); e = list_next(e)) {
      struct semaphore_elem *sema_elem = list_entry(e, struct semaphore_elem, elem);

      // list_front 쓰기전에 원소가 있는지 없는지 먼저 확인할 것
      struct thread *waiting_thread = list_entry(list_front(&sema_elem->semaphore.waiters), struct thread, elem);

      if (waiting_thread->priority > max_priority) {
        max_priority = waiting_thread->priority;
        max_elem = e;
      }
    }
    if (max_elem != NULL) {
      struct semaphore_elem *max_sema_elem = list_entry(max_elem, struct semaphore_elem, elem);
      list_remove(max_elem);
      sema_up(&max_sema_elem->semaphore);
    }
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters)) cond_signal(cond, lock);
}
