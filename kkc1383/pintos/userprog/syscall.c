#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* system call */
static void system_halt(void);
static pid_t system_fork(const char *thread_name, struct intr_frame *f);
static int system_exec(const char *cmdd_line);
static int system_wait(pid_t pid);
static bool system_create(const char *file, unsigned initial_size);
static bool system_remove(const char *file);
static int system_open(const char *file);
static int system_filesize(int fd);
static int system_read(int fd, void *buffer, unsigned size);
static int system_write(int fd, const void *buffer, unsigned size);
static void system_seek(int fd, unsigned position);
static unsigned system_tell(int fd);
static int system_dup2(int oldfd, int newfd);

static void validate_user_string(const char *str);
static int expend_fd_table(struct thread *curr, size_t size);

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

struct lock filesys_lock; /* filesys 함수 접근 시 동기화 용 */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  lock_init(&filesys_lock);
  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  switch (f->R.rax) {
    case SYS_HALT:
      system_halt();
      break;
    case SYS_EXIT:
      system_exit(f->R.rdi);
      break;
    case SYS_FORK:
      f->R.rax = system_fork(f->R.rdi, f);
      break;
    case SYS_EXEC:
      f->R.rax = system_exec(f->R.rdi);
      break;
    case SYS_WAIT:
      f->R.rax = system_wait(f->R.rdi);
      break;
    case SYS_CREATE:
      f->R.rax = system_create(f->R.rdi, f->R.rsi);
      break;
    case SYS_REMOVE:
      f->R.rax = system_remove(f->R.rdi);
      break;
    case SYS_OPEN:
      f->R.rax = system_open(f->R.rdi);
      break;
    case SYS_FILESIZE:
      f->R.rax = system_filesize(f->R.rdi);
      break;
    case SYS_READ:
      f->R.rax = system_read(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_WRITE:
      f->R.rax = system_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      system_seek(f->R.rdi, f->R.rsi);
      break;
    case SYS_TELL:
      f->R.rax = system_tell(f->R.rdi);
      break;
    case SYS_CLOSE:
      system_close(f->R.rdi);
      break;
    case SYS_DUP2:
      f->R.rax = system_dup2(f->R.rdi, f->R.rsi);
      break;
    default:
      printf("unknown! %d\n", f->R.rax);
      thread_exit();
      break;
  }
}
static void system_halt(void) { power_off(); }
void system_exit(int status) {
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
static pid_t system_fork(const char *thread_name, struct intr_frame *f) { return process_fork(thread_name, f); }
static int system_exec(const char *cmdd_line) {
  validate_user_string(cmdd_line);
  int result = process_exec(cmdd_line);
  system_exit(result);
  // never reached!!
  return result;  // 실패했을 경우에만 반환
}
static int system_wait(pid_t pid) { return process_wait(pid); }
static bool system_create(const char *file, unsigned initial_size) {
  validate_user_string(file);  // file이 널 문자인지, 혹은 페이지 테이블에 없는 주소인지
  // 대신에 락이 걸려야함
  lock_acquire(&filesys_lock);                       // 동시접근을 막기 위해
  bool result = filesys_create(file, initial_size);  // 파일 생성
  lock_release(&filesys_lock);
  return result;  // 파일 생성이 성공적이면 true, 아니면 false
}
static bool system_remove(const char *file) {
  validate_user_string(file);          // file이 널 문자인지, 혹은 페이지 테이블에 없는 주소인지
  lock_acquire(&filesys_lock);         // 동시접근을 막기 위해
  bool result = filesys_remove(file);  // 파일 삭제
  lock_release(&filesys_lock);
  return result;  // 파일 삭제가 성공적이면 true, 아니면 false
}
static int system_open(const char *file) {
  validate_user_string(file);   // file 이 널문자인지, 혹은 페이지 테이블에 없는 주소인지
  lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
  struct file *open_file = filesys_open(file);  // 파일 열기
  lock_release(&filesys_lock);
  if (!open_file) return -1;  //파일 열기 실패 시 종료

  // fd 할당
  struct thread *curr = thread_current();

  //빈 공간 찾기
  int new_fd = -1;
  for (int i = 0; i < curr->fd_size; i++) {
    if (!curr->fd_table[i]) {
      new_fd = i;  //빈공간에 new_fd 설정
      break;
    }
  }

  if (new_fd == -1) {  // 확장이 필요하다면
    if (expend_fd_table(curr, 1) < 0) {
      // 확장 실패 했다면
      lock_acquire(&filesys_lock);
      file_close(open_file);  //파일 닫고
      lock_release(&filesys_lock);
      return -1;  //-1 리턴하고 종료
    }
    new_fd = curr->fd_max + 1;  //확장 후 new_fd 설정
  }
  if (curr->fd_max < new_fd) curr->fd_max = new_fd;  // fd_max 갱신

  curr->fd_table[new_fd] = open_file;
  // rox 구현
  if (!strcmp(curr->name, file)) file_deny_write(open_file);  // 본인 자신을 열려고 하면 deny_write 설정

  return new_fd;
}
static int system_filesize(int fd) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return -1;  // fd가 유효하지 않은 숫자일 경우
  if (curr->fd_table[fd] == get_std_in() || curr->fd_table[fd] == get_std_out())  // 표준 입출력일 경우
    return -1;                                                                    // -1 리턴하고 종료
  int file_size = -1;        //해당 fd에 파일이 없을때 -1 리턴하기 위해
  if (curr->fd_table[fd]) {  //해당 fd에 파일이 있다면
    lock_acquire(&filesys_lock);
    file_size = file_length(curr->fd_table[fd]);
    lock_release(&filesys_lock);
  }
  return file_size;  // filesize 반환
}
static int system_read(int fd, void *buffer, unsigned size) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return -1;  // fd가 유효하지 않은 숫자일 경우
  validate_user_string(buffer);

  int read_bytes;
  if (curr->fd_table[fd] == get_std_in()) {  //표준입력인 경우
    read_bytes = input_getc();
  } else if (curr->fd_table[fd] == get_std_out()) {  // 표준 출력일 경우 잘못된 접근이므로 -1리턴
    return -1;
  } else {
    struct file *read_file = curr->fd_table[fd];
    if (!read_file) return -1;
    lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
    read_bytes = file_read(read_file, buffer, size);
    lock_release(&filesys_lock);
  }

  return read_bytes;
}
static int system_write(int fd, const void *buffer, unsigned size) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return -1;  // fd가 유효하지 않은 숫자일 경우
  validate_user_string(buffer);

  if (curr->fd_table[fd] == get_std_out()) {  // 표준 출력일 경우
    putbuf(buffer, size);
    return size;
  } else if (curr->fd_table[fd] == get_std_in()) {  //표준 입력일 경우 잘못된 접근이므로 -1 리턴
    return -1;
  } else {
    int write_bytes;
    struct file *write_file = curr->fd_table[fd];
    if (!write_file) return -1;
    if (write_file->deny_write) return 0;
    lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
    write_bytes = file_write(write_file, buffer, size);
    lock_release(&filesys_lock);
    return write_bytes;
  }
}
static void system_seek(int fd, unsigned position) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return;  // fd가 유효하지 않은 숫자일 경우
  if (curr->fd_table[fd] == get_std_in() ||
      curr->fd_table[fd] == get_std_out())  // 표준 입출력은 잘못된 접근이므로 -1 리턴
    return -1;
  struct file *seek_file = curr->fd_table[fd];
  if (!seek_file) return;  // fd size 이내의 숫자이지만 열린 fd가 아니라면 리턴

  lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
  file_seek(seek_file, position);
  lock_release(&filesys_lock);
}
static unsigned system_tell(int fd) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return 0;  // fd가 유효하지 않은 숫자일 경우
  if (curr->fd_table[fd] == get_std_in() ||
      curr->fd_table[fd] == get_std_out())  // 표준 입출력은 잘못된 접근이므로 -1 리턴
    return -1;
  struct file *tell_file = curr->fd_table[fd];
  if (!tell_file) return 0;  // fd size 이내의 숫자이지만 열린 fd가 아니라면 리턴

  lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
  unsigned tell_bytes = file_tell(tell_file);
  lock_release(&filesys_lock);
  return tell_bytes;
}
void system_close(int fd) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd >= curr->fd_size) return;  // fd가 유효하지 않은 숫자일 경우
  struct file *close_file = curr->fd_table[fd];
  if (!close_file) return;  // fd size 이내의 숫자이지만 열린 fd가 아니라면 리턴

  if (curr->fd_table[fd] != get_std_in() && curr->fd_table[fd] != get_std_out()) {  // 표준 입출력이 아닐 경우
    if (close_file->dup_count >= 2) {  // 누군가 dup2 되어있을 경우
      close_file->dup_count--;         // dup_count만 내려줍니다.
    } else {
      lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
      file_close(close_file);       // file 닫아주기
      lock_release(&filesys_lock);
    }
  }
  curr->fd_table[fd] = NULL;  // fd_table에서 빼주기
}
static int system_dup2(int oldfd, int newfd) {
  struct thread *curr = thread_current();
  // oldfd가 유효한 파일 디스크립터가 아니라면 -1 반환 후 종료, newfd가 음수여도 종료
  if (oldfd < 0 || curr->fd_table[oldfd] == NULL || newfd < 0) return -1;
  // oldfd == newfd 라면 그냥 newfd 반환 후 별도 동작없이 종료
  if (oldfd == newfd) return newfd;

  /* newfd가 열려있는 fd라면 fd 닫기 (newfd에 파일이 없거나, 표준 입출력일 경우는 제외)*/
  if (curr->fd_table[newfd] != NULL && newfd <= curr->fd_max) {
    system_close(newfd);
  }
  /* 본격적인 dup2 동작 */

  // newfd가 현재 fd_table에 없는 숫자일 경우 확장
  if (newfd >= curr->fd_size) {
    if (expend_fd_table(curr, newfd - curr->fd_size + 1) < 0)
      return -1;  //필요한 만큼만 확장(알아서 MAX_FILES 정렬해줌)
  }
  // oldfd가 표준 입출력일 경우 그냥 가져오기만 하면됨
  if (curr->fd_table[oldfd] == get_std_in() || curr->fd_table[oldfd] == get_std_out()) {
    curr->fd_table[newfd] = curr->fd_table[oldfd];
  } else {  //일반 파일일 경우
    struct file *dup_file = curr->fd_table[oldfd];
    curr->fd_table[newfd] = dup_file;  // 그냥 포인터만 가져옴
    dup_file->dup_count++;             // dup_count 증가
  }
  if (newfd > curr->fd_max) curr->fd_max = newfd;  // fd_max 갱신
  return newfd;
}

static void validate_user_string(const char *str) {
  if (str == NULL || !is_user_vaddr(str)) {  //주소가 NULL이거나, kernel 영역이거나
    system_exit(-1);                         // 종료
  }
  if (pml4_get_page(thread_current()->pml4, str) == NULL) {  // 해당 프로세스의 page테이블에 등록되어 있지 않는 주소라면
    system_exit(-1);                                         //종료
  }
}
static int expend_fd_table(struct thread *curr, size_t size) {  // MAXFILES의 배수로 ㄱㄱ
  // if (curr->fd_size >= 512) return -1;                          //크기 제한
  size_t size_cnt = size / MAX_FILES + 1;
  size_t expend_size = size_cnt * MAX_FILES;
  // MAX_FILES의 배수만큼만 확장
  struct file **new_table =
      (struct file **)calloc((curr->fd_size + expend_size), sizeof(struct file *));  //새로 이사갈 주소
  if (new_table == NULL) return -1;                                                  //재할당에 실패했을 경우
  memcpy(new_table, curr->fd_table, curr->fd_size * sizeof(struct file *));          // 메모리 이사(값 옮기기)
  free(curr->fd_table);                                                              // 기존에 있던 곳 free
  curr->fd_table = new_table;
  curr->fd_size += expend_size;
  return 0;  // 성공적일 경우 0반환
}