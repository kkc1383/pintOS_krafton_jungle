#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* system call */
static void system_exit(int status);
static int system_write(int fd, const void *buffer, unsigned size);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  switch (f->R.rax) {
    case SYS_EXIT:
      system_exit(f->R.rdi);
      break;
    case SYS_WRITE:
      f->R.rax = system_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
  }
}

static void system_exit(int status) {
  /* child_list에 종료되었음을 기록, status, has_exited 등 */
  // 여기에 한 이유는 status가 process_exit()까지 못간다. 인자로 넘기려니 고칠게 너무많음.
  struct thread *curr = thread_current();
  struct thread *parent = thread_get_by_tid(curr->parent_tid);
  if (!parent) {
    // 고아처리
    return;
  }
  lock_acquire(&parent->children_lock);  // child_list 순회하기 때문에
  // tid로 child_info list에서 본인 노드 찾기
  struct list_elem *e;
  for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
    struct child_info *child = list_entry(e, struct child_info, child_elem);
    if (child->child_tid == curr->tid) {  // 본인노드 찾아서 semaup 하기
      child->exit_status = status;        // status 설정
      child->has_exited = true;
      sema_up(&child->wait_sema);  // wait 중인 부모 깨우기
      break;
    }
  }
  lock_release(&parent->children_lock);  // child_list 순회하기 때문에
  printf("%s: exit(%d)\n", curr->name, status);
  thread_exit();
}
static int system_write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
}
