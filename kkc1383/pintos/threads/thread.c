#include "threads/thread.h"

#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/fixed-point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list sleep_list;  // sleep_list를 관리할 이중 연결리스트 생성
static struct list all_list;    // 모든 스레드를 관리함

/* MLQFS 전용 다중 큐*/
static struct list mlfqs_ready_queues[PRI_MAX - PRI_MIN + 1];
static int ready_threads_count;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* mlfqs global variables */
static fixed_t load_avg; /* 시스템 부하 평균 (fixed-point) */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);
static int max_priority_mlfqs_queue(void);
static void thread_update_recent_cpu(struct thread *t);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  /* Reload the temporal gdt for the kernel
   * This gdt does not include the user context.
   * The kernel will rebuild the gdt with user context, in gdt_init (). */
  struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1, .address = (uint64_t)gdt};
  lgdt(&gdt_ds);

  /* Init the global thread context */
  lock_init(&tid_lock);
  list_init(&ready_list);
  list_init(&sleep_list);
  list_init(&all_list);
  list_init(&destruction_req);

  /* mlfqs 초기화 */
  load_avg = INT_TO_FP(0); /* load_avg 를 0.0으로 초기화 */

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;  // 이거 순서 매우 중요함
  initial_thread->tid = allocate_tid();
  list_push_front(&all_list, &initial_thread->all_elem);

  if (thread_mlfqs) {
    mlfqs_update_priority(initial_thread);  // 첫 main쓰레드 priority 설정(PRI_MAX)

    // mlfqs_ready_queues에는 PRI_MIN을 시작으로 PRI_MAX까지 우선순위별 다중 큐임
    for (int i = PRI_MIN; i <= PRI_MAX; i++) {
      list_init(&mlfqs_ready_queues[i - PRI_MIN]);
    }
    ready_threads_count = 0;  // 0으로 초기화

  } else
    printf("Priority scheduler enabled\n");
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread) idle_ticks++;
#ifdef USERPROG
  else if (t->pml4 != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE) intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority, thread_func *function, void *aux) {
  struct thread *t;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL) return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();
  list_push_back(&all_list, &t->all_elem);  // all_list에 원소 넣기

  if (thread_mlfqs) {  // mlfqs일 경우
    struct thread *parent = thread_current();
    // 부모 쓰레드의 nice, recent_cpu 물려받기
    if (parent != NULL) {
      t->nice = parent->nice;
      t->recent_cpu = parent->recent_cpu;
    }
    mlfqs_update_priority(t);  // priority 공식으로 계산
  }

  /* Call the kernel_thread if it scheduled.
   * Note) rdi is 1st argument, and rsi is 2nd argument. */
  t->tf.rip = (uintptr_t)kernel_thread;
  t->tf.R.rdi = (uint64_t)function;
  t->tf.R.rsi = (uint64_t)aux;
  t->tf.ds = SEL_KDSEG;
  t->tf.es = SEL_KDSEG;
  t->tf.ss = SEL_KDSEG;
  t->tf.cs = SEL_KCSEG;
  t->tf.eflags = FLAG_IF;

  /* Add to run queue. */
  thread_unblock(t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);
  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();           // 인터럽트를 disable상태로 만들고 이전 상태를
                                        // 반환(기존 상태 저장해놓고, disable 만듬)
  ASSERT(t->status == THREAD_BLOCKED);  // 해당 쓰레드의 status 필드가 THREAD_BLOCKED인지 확인

  if (thread_mlfqs) {
    list_push_back(&mlfqs_ready_queues[t->priority - PRI_MIN], &t->elem);  // 우선순위에 맞는 큐에 집어넣음
    if (t != idle_thread)  // idle thread는 카운트 하면 안되므로
      ready_threads_count++;
  } else {
    list_insert_ordered(&ready_list, &t->elem, thread_priority_less, NULL);  // 우선순위 큰 순서대로 삽입
  }
  t->status = THREAD_READY;  // 해당 쓰레드의 상태를 THREAD_READY로 바꿈

  // 인터럽트끝나고 보내야할 경우에
  if (t->priority > thread_current()->priority) {
    if (intr_context()) {
      // 인터럽트 핸들러 내부: 나중에 yield
      intr_yield_on_return();
    } else if (thread_current() != idle_thread) {  // idle은 yield하지 않도록
      // 일반 컨텍스트: 플래그 설정
      intr_set_level(old_level);
      thread_yield();
      return;  // 여기는 더 이상 할 게 없으므로 리턴
    }
  } else {
    intr_set_level(old_level);
  }
}
/* Returns the name of the running thread. */
const char *thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *thread_current(void) {
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /* Just set our status to dying and schedule another process.
     We will be destroyed during the call to schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->all_elem);  // all_list에서 제거
  do_schedule(THREAD_DYING);
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {  // 현재 스레드가 가장 높은 우선순위를 가진다면
  struct thread *curr = thread_current();

  ASSERT(!intr_context());

  enum intr_level old_level = intr_disable();
  if (curr != idle_thread) {
    if (thread_mlfqs) {  // mlfqs 모드인 경우
      int max_priority = max_priority_mlfqs_queue();
      if (max_priority >= 0) {  // 전체 큐가 비어있지 않은 경우
        if (curr->priority > max_priority) {
          intr_set_level(old_level);
          return;
        }
      }
      list_push_back(&mlfqs_ready_queues[curr->priority - PRI_MIN],
                     &curr->elem);  // 본인 우선순위에 맞는 레디큐로 들어감
      ready_threads_count++;
    } else {
      if (!list_empty(&ready_list)) {
        struct thread *highest = list_entry(list_front(&ready_list), struct thread, elem);

        if (curr->priority > highest->priority) {  // 현재 쓰레드가 ready_list에 있는 쓰레드들보다 우선순위가 높다면
          intr_set_level(old_level);
          return;  // yield를 할 필요가 없음.
        }
      }
      list_insert_ordered(&ready_list, &curr->elem, thread_priority_less, NULL);  // 우선순위 순으로 정렬하며 삽입
    }
  }
  do_schedule(THREAD_READY);
  intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
  if (thread_mlfqs) return;  // mlfqs에서는 발동하지 않기, 즉시 리턴

  struct thread *curr = thread_current();
  int old_priority = curr->priority;

  // donate를 안받은 경우에는 priority를 바꿔주어야 함. // lock_release에서 적당한 priority로 바꿔 줄거라서
  if (curr->is_donated == 0) curr->priority = new_priority;
  curr->original_priority = new_priority;
  if (old_priority > new_priority) {  // 만약 우선순위가 더 낮아졌고, ready_list에 원소가 있을 떄
    thread_yield();                   // yield를 통해 뒤로 보냄
  }
}
// thread_update_all_priority 생성해야함
void thread_update_all_priority(void) {
  enum intr_level old_level = intr_disable();  // 인터럽트 끄기
  struct list_elem *e;                         // all_list 순회 시 사용하는 iterator
  struct list new_ready_queue;                 // ready 큐 임시 저장(싹다 뺐다가 싹다 넣을 거임)
  list_init(&new_ready_queue);                 // new_ready 큐 초기화

  /* all list 순회하며 priority 갱신 */
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, all_elem);
    if (t == idle_thread) continue;                // idle 쓰레드는 제외
    if (t->status == THREAD_READY) {               // ready queue에 있던 thread라면
      list_remove(&t->elem);                       // 기존에 있던 ready queue에서 빼고
      list_push_back(&new_ready_queue, &t->elem);  //임시 저장 큐에 집어넣기
    }
    mlfqs_update_priority(t);  // priority 조정
  }

  // ready 큐들은 다시 다중 큐에 집어 넣기
  while (!list_empty(&new_ready_queue)) {
    e = list_pop_front(&new_ready_queue);
    struct thread *t = list_entry(e, struct thread, elem);
    list_push_back(&mlfqs_ready_queues[t->priority - PRI_MIN], e);
  }

  // 혹시 현재 스레드의 우선순위가 레디큐에 있는 쓰레드보다 작거나 같다면 양보해야함
  if (thread_current()->priority <= max_priority_mlfqs_queue()) {
    if (intr_context()) {
      intr_yield_on_return();
    } else {
      intr_set_level(old_level);  // 인터럽트 풀어주고
      thread_yield();             // 양보
      return;
    }
  }

  intr_set_level(old_level);  // 인터럽트 복원
}
void mlfqs_update_priority(struct thread *t) {
  if (!thread_mlfqs) return;  // mlqfs 가 아니라면 나가라

  ASSERT(t != NULL);

  /* recent CPU /4 */
  int recent_cpu_div4 = FP_TO_INT_ZERO(DIV_FP_INT(t->recent_cpu, 4));  // recent_cpu 나누기 4를 정수로 절삭한거

  /* nice * 2 */
  int nice_mul2 = t->nice + FP_TO_INT_ZERO(MULT_FP_INT(FP_59_60, t->nice));  // 1.98
  // int nice_mul2 = t->nice * 2;

  /* priority = PRI_MAX - recent_cpu/4 - nice *2 */
  int new_priority = PRI_MAX - recent_cpu_div4 - nice_mul2;

  /* [PRI_MIN,PRI,MAX] 범위를 벗어나지 않게 조절 */
  if (new_priority > PRI_MAX) new_priority = PRI_MAX;  // max를 넘어갔으면 max로
  if (new_priority < PRI_MIN) new_priority = PRI_MIN;  // min을 넘어갔으면 min으로

  t->priority = new_priority;
}

/* Returns the current thread's priority. */
int thread_get_priority(void) { return thread_current()->priority; }

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice) {
  // nice를 [-20,20] 범위로 제한 :
  if (nice > 20)
    nice = 20;
  else if (nice < -20)
    nice = -20;

  enum intr_level old_level = intr_disable();
  //현재 스레드의 nice 값 업데이트
  struct thread *curr = thread_current();
  curr->nice = nice;
  // 자신의 priority 재계산
  mlfqs_update_priority(curr);

  // 만약 자신이 더 이상 최고 priority가 아니면 양보
  /* 조건보고 양보하는 경우 (다른 쓰레드에 의해서 race 발생해서 max가 바뀔수도 있음)*/
  if (curr->priority <= max_priority_mlfqs_queue()) {
    if (intr_context()) {
      intr_yield_on_return();
    } else {
      intr_set_level(old_level);
      thread_yield();
      return;
    }
  }
  intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) { return thread_current()->nice; }

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) { return FP_TO_INT_ZERO(MULT_FP_INT(load_avg, 100)); }
// timer_interrupt 함수에서 구현했으면 getter함수때문에 가독성이 떨어질까봐 접근이 쉬운 thread.c에서 구현
void thread_update_load_avg(void) {
  int running_and_ready_thread_count =
      ready_threads_count + is_not_idle(thread_current());  // 현재 스레드도 갯수에 포함해야 하는데, idle은 포함 x
  // load_avg = (59/60) * load_avg + (1/60) * ready_threads_count;
  load_avg = ADD_FP(MULT_FP(FP_59_60, load_avg), MULT_FP_INT(FP_1_60, running_and_ready_thread_count));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) { return FP_TO_INT_ZERO(MULT_FP_INT(thread_current()->recent_cpu, 100)); }
void thread_update_all_recent_cpu(void) {
  struct list_elem *e;  // thread_list 순회 시 사용하는 iterator

  /* all list 순회하며 recent_cpu 갱신 */
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, all_elem);
    if (t != idle_thread) thread_update_recent_cpu(t);
  }
}
// 각 리스트 별로 매크로 떡칠인 라인을 넣자니 너무 지저분해서 따로 함수로 만듬
/* recent_cpu = load_avg * 2 / (load_avg * 2 + 1 ) + nice */
static void thread_update_recent_cpu(struct thread *t) {
  t->recent_cpu = ADD_FP_INT(
      MULT_FP(DIV_FP(MULT_FP_INT(load_avg, 2), ADD_FP_INT(MULT_FP_INT(load_avg, 2), 1)), t->recent_cpu), t->nice);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
  struct semaphore *idle_started = idle_started_;

  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {
  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
  t->magic = THREAD_MAGIC;

  t->wake_tick = 0;  // 깨워야하는 시간 초기화

  t->priority = priority;
  t->original_priority = priority;
  list_init(&t->acquired_locks);
  t->waiting_for_lock = NULL;
  t->is_donated = 0;

  /* mlfqs 멤버 초기화 */
  t->nice = 0;
  t->recent_cpu = INT_TO_FP(0);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *next_thread_to_run(void) {
  if (thread_mlfqs) {  // mlfqs 일 때
    int max_priority;
    if ((max_priority = max_priority_mlfqs_queue()) >= 0) {  // ready 다중 큐에서 존재하는 가장 높은 prioirty 반환
      ready_threads_count--;                                 // ready_thread_count를 뺌
      struct thread *selected =
          list_entry(list_pop_front(&mlfqs_ready_queues[max_priority - PRI_MIN]), struct thread, elem);
      return selected;
    } else  // 큐에 존재하는 쓰레드가 없을 때
      return idle_thread;
  } else {  // 일반적인 경우 일 때
    if (list_empty(&ready_list))
      return idle_thread;
    else
      return list_entry(list_pop_front(&ready_list), struct thread, elem);
  }
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf) {
  __asm __volatile(
      "movq %0, %%rsp\n"
      "movq 0(%%rsp),%%r15\n"
      "movq 8(%%rsp),%%r14\n"
      "movq 16(%%rsp),%%r13\n"
      "movq 24(%%rsp),%%r12\n"
      "movq 32(%%rsp),%%r11\n"
      "movq 40(%%rsp),%%r10\n"
      "movq 48(%%rsp),%%r9\n"
      "movq 56(%%rsp),%%r8\n"
      "movq 64(%%rsp),%%rsi\n"
      "movq 72(%%rsp),%%rdi\n"
      "movq 80(%%rsp),%%rbp\n"
      "movq 88(%%rsp),%%rdx\n"
      "movq 96(%%rsp),%%rcx\n"
      "movq 104(%%rsp),%%rbx\n"
      "movq 112(%%rsp),%%rax\n"
      "addq $120,%%rsp\n"
      "movw 8(%%rsp),%%ds\n"
      "movw (%%rsp),%%es\n"
      "addq $32, %%rsp\n"
      "iretq"
      :
      : "g"((uint64_t)tf)
      : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void thread_launch(struct thread *th) {
  uint64_t tf_cur = (uint64_t)&running_thread()->tf;
  uint64_t tf = (uint64_t)&th->tf;
  ASSERT(intr_get_level() == INTR_OFF);

  /* The main switching logic.
   * We first restore the whole execution context into the intr_frame
   * and then switching to the next thread by calling do_iret.
   * Note that, we SHOULD NOT use any stack from here
   * until switching is done. */
  __asm __volatile(
      /* Store registers that will be used. */
      "push %%rax\n"
      "push %%rbx\n"
      "push %%rcx\n"
      /* Fetch input once */
      "movq %0, %%rax\n"
      "movq %1, %%rcx\n"
      "movq %%r15, 0(%%rax)\n"
      "movq %%r14, 8(%%rax)\n"
      "movq %%r13, 16(%%rax)\n"
      "movq %%r12, 24(%%rax)\n"
      "movq %%r11, 32(%%rax)\n"
      "movq %%r10, 40(%%rax)\n"
      "movq %%r9, 48(%%rax)\n"
      "movq %%r8, 56(%%rax)\n"
      "movq %%rsi, 64(%%rax)\n"
      "movq %%rdi, 72(%%rax)\n"
      "movq %%rbp, 80(%%rax)\n"
      "movq %%rdx, 88(%%rax)\n"
      "pop %%rbx\n"  // Saved rcx
      "movq %%rbx, 96(%%rax)\n"
      "pop %%rbx\n"  // Saved rbx
      "movq %%rbx, 104(%%rax)\n"
      "pop %%rbx\n"  // Saved rax
      "movq %%rbx, 112(%%rax)\n"
      "addq $120, %%rax\n"
      "movw %%es, (%%rax)\n"
      "movw %%ds, 8(%%rax)\n"
      "addq $32, %%rax\n"
      "call __next\n"  // read the current rip.
      "__next:\n"
      "pop %%rbx\n"
      "addq $(out_iret -  __next), %%rbx\n"
      "movq %%rbx, 0(%%rax)\n"  // rip
      "movw %%cs, 8(%%rax)\n"   // cs
      "pushfq\n"
      "popq %%rbx\n"
      "mov %%rbx, 16(%%rax)\n"  // eflags
      "mov %%rsp, 24(%%rax)\n"  // rsp
      "movw %%ss, 32(%%rax)\n"
      "mov %%rcx, %%rdi\n"
      "call do_iret\n"
      "out_iret:\n"
      :
      : "g"(tf_cur), "g"(tf)
      : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void do_schedule(int status) {
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(thread_current()->status == THREAD_RUNNING);
  while (!list_empty(&destruction_req)) {
    struct thread *victim = list_entry(list_pop_front(&destruction_req), struct thread, elem);
    palloc_free_page(victim);
  }
  thread_current()->status = status;
  schedule();
}

static void schedule(void) {
  struct thread *curr = running_thread();      // 레지스터 rsp를 활용하여 현재 돌고
                                               // 있는 쓰레드 포인터를 찾음
  struct thread *next = next_thread_to_run();  // ready_list에서 쓰레드 하나를 pop 함.
                                               // ready_list에서 뽑을 마땅한 쓰레드가 없다면 idle
                                               // 반환

  ASSERT(intr_get_level() == INTR_OFF);    // 인터럽트가 disable상태인지 확인
  ASSERT(curr->status != THREAD_RUNNING);  // 현재 쓰레드가 제대로 THREAD_RUNNING가 아니게
                                           // 되었는지 확인
  ASSERT(is_thread(next));                 // next로 받은 쓰레드가 제대로 갖춰진 쓰레드인지
  /* Mark us as running. */
  next->status = THREAD_RUNNING;  // next 쓰레드의 상태를 THREAD_RUNNING으로 바꿔준다.

  /* Start new time slice. */
  thread_ticks = 0;  // 쓰레드가 yield 한 이후로 지난 시간, 0으로 세팅

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate(next);
#endif

  if (curr != next) {
    /* If the thread we switched from is dying, destroy its struct
       thread. This must happen late so that thread_exit() doesn't
       pull out the rug under itself.
       We just queuing the page free request here because the page is
       currently used by the stack.
       The real destruction logic will be called at the beginning of the
       schedule(). */
    if (curr && curr->status == THREAD_DYING && curr != initial_thread) {  // curr이 DYING 하는 쓰레드라면 즉시
                                                                           // 삭제하는게 아니라
      ASSERT(curr != next);
      list_push_back(&destruction_req,
                     &curr->elem);  // destruction_req에 넣어놨다가 다른
                                    // 쓰레드에 의해서 청소 되게끔
    }

    /* Before switching the thread, we first save the information
     * of current running. */
    thread_launch(next);  // 쓰레드별 context switch가 일어나는 함수, 기존에
                          // 쓰던 환경들을 push로 저장해두고, 다음 쓰레드를 실행
  }
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

struct list *get_ready_list(void) {
  return &ready_list;
}
struct list *get_sleep_list(void) {
  return &sleep_list;
}

bool thread_priority_less(const struct list_elem *a, const struct list_elem *b, void *aux) {
  struct thread *thread_a = list_entry(a, struct thread, elem);
  struct thread *thread_b = list_entry(b, struct thread, elem);

  return thread_a->priority > thread_b->priority;
}

static int max_priority_mlfqs_queue(void) {  // mlfqs에서 존재하는 ready_thread 중 가장 높은 우선순위를 반환
  for (int i = PRI_MAX; i >= PRI_MIN; i--) {  // 우선순위 다중 ready 큐 순회, 우선순위 높은 순으로
    if (!list_empty(&mlfqs_ready_queues[i - PRI_MIN])) {  //노드가 있는 큐를 찾았으면
      return i;
    }
  }
  return -1;  //아예 비어있다면
}

bool is_not_idle(struct thread *t) { return t != idle_thread; }
