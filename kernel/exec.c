#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

// loadseg 함수의 첫 번째 인자 타입을 pagetable_t로 수정했습니다.
static int loadseg(pagetable_t, uint64, struct inode *, uint, uint);

int flags2perm(int flags)
{
    int perm = 0;
    if(flags & ELF_PROG_FLAG_EXEC) // ELF 헤더의 실행 권한 플래그 사용
      perm = PTE_X;
    if(flags & ELF_PROG_FLAG_WRITE) // ELF 헤더의 쓰기 권한 플래그 사용
      perm |= PTE_W;
    // ELF 플래그에는 보통 읽기(R) 권한도 있으나, xv6에서는 X 또는 W가 있으면 R은 기본으로 간주하거나,
    // uvmalloc/mappages에서 PTE_U와 함께 PTE_R을 기본으로 설정하는 경우가 많습니다.
    // 여기서는 명시적으로 PTE_R을 추가하려면 flags2perm 또는 uvmalloc 호출 시 추가해야 합니다.
    // 일반적으로 사용자 페이지는 읽기 가능해야 하므로 PTE_R을 추가하는 것이 안전합니다.
    if (flags & ELF_PROG_FLAG_READ) // 명시적 읽기 권한
        perm |= PTE_R;
    if (perm == 0 && (flags & ELF_PROG_FLAG_READ)) // 읽기 전용 세그먼트 처리
        perm = PTE_R;

    return perm;
}

int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz_elf = 0, sp, ustack[MAXARG], stackbase; // sz_elf는 ELF 로드 후의 크기
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable = 0; // oldpagetable 초기화
  struct proc *p = myproc();
  uint64 oldsz = 0; // oldsz 선언 및 초기화
  uint64 final_sz = 0; // bad 레이블에서 사용할 최종 크기 변수

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Check ELF header
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Load program into memory.
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr) // Address overflow
      goto bad;
    if(ph.vaddr % PGSIZE != 0) // Not page-aligned
      goto bad;
    
    uint64 current_program_size;
    // ELF 세그먼트를 위한 메모리 할당 및 권한 설정 (PTE_U는 uvmalloc에서 처리 가정)
    // 읽기 권한(PTE_R)은 대부분의 사용자 세그먼트에 필요하므로 기본 추가
    int perm = flags2perm(ph.flags) | PTE_R;
    if((current_program_size = uvmalloc(pagetable, sz_elf, ph.vaddr + ph.memsz, perm)) == 0)
      goto bad;
    sz_elf = current_program_size;
    
    if(loadseg(pagetable, ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  p = myproc();
  oldsz = p->sz; // 이전 프로세스의 크기 (해제 시 사용)
  oldpagetable = p->pagetable; // 이전 페이지 테이블 (해제 시 사용)

  // 여기서부터 새로운 스택 할당 로직 (기존 스택 할당 코드는 제거됨)
  #define USTACKPAGES 1 // 사용자 스택으로 사용할 페이지 수

  // 1. MAXVA 바로 아래에 스택 페이지들을 명시적으로 할당 및 매핑합니다.
  for (uint64 va_stk = MAXVA - USTACKPAGES*PGSIZE; va_stk < MAXVA; va_stk += PGSIZE) {
    char *mem = kalloc();
    if (mem == 0) {
      final_sz = sz_elf; // 실패 시점까지의 크기로 설정 (ELF 로드 부분만)
      goto bad; 
    }
    // 사용자 스택은 읽고 쓸 수 있어야 합니다 (PTE_U, PTE_R, PTE_W).
    if (mappages(pagetable, va_stk, PGSIZE, (uint64)mem, PTE_U | PTE_R | PTE_W) != 0) {
      kfree(mem);
      final_sz = sz_elf; // 실패 시점까지의 크기로 설정
      goto bad;
    }
  }

  // 2. 새로운 스택 포인터(sp)는 MAXVA로 설정 (스택은 아래로 자람).
  sp = MAXVA;
  stackbase = MAXVA - USTACKPAGES*PGSIZE; // 스택의 가장 낮은 주소 (경계)

  // 3. 프로세스의 전체 크기를 나타낼 변수에 MAXVA를 할당합니다.
  //    이 값은 최종적으로 p->sz에 반영됩니다.
  final_sz = MAXVA;

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad; // final_sz는 MAXVA로 설정된 상태로 bad로 감
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // RISC-V SP는 16바이트 정렬
    if(sp < stackbase) // 스택 오버플로우 (stackbase 침범)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0; // argv 배열의 끝은 NULL 포인터

  // Push the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // arguments to user main(argc, argv)
  // argc는 시스템 콜 반환 값 (a0)을 통해 전달됩니다.
  // argv는 p->trapframe->a1 (두 번째 인자 레지스터)을 통해 전달됩니다.
  p->trapframe->a1 = sp; // main의 argv 인자 (사용자 스택 상의 주소)

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the new user image.
  p->pagetable = pagetable;
  p->sz = final_sz; // 최종 프로세스 크기를 MAXVA로 설정
  p->trapframe->epc = elf.entry;  // 프로그램 시작 주소 (main)
  p->trapframe->sp = sp;          // 최종 사용자 스택 포인터
  
  // 이전 페이지 테이블과 메모리 해제
  if(oldpagetable) // oldpagetable이 NULL이 아닐 경우에만 해제
    proc_freepagetable(oldpagetable, oldsz);

  return argc; // main의 argc 인자 (a0 레지스터에 저장됨)

bad:
  // 오류 발생 시 할당된 자원 해제
  if(pagetable) // 새 페이지 테이블이 생성되었다면 해제
    proc_freepagetable(pagetable, final_sz); // final_sz는 오류 발생 지점에 따라 다를 수 있으나,
                                         // 여기서는 스택 할당까지 고려한 MAXVA 또는 그 이전의 sz_elf가 될 수 있음.
                                         // 좀 더 정교한 오류 처리가 필요할 수 있음.
                                         // 현재는 final_sz를 사용.
  if(ip){ // inode가 아직 사용 중이면 해제
    iunlockput(ip);
    end_op();
  }
  return -1;
}

// Load a program segment into pagetable at virtual address va.
// va must be page-aligned.
// sz (세그먼트 크기) 만큼 ip inode의 offset부터 읽어서 va에 로드합니다.
// 해당 va 영역의 페이지들은 이미 uvmalloc 등을 통해 매핑되어 있어야 합니다.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  for(i = 0; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, va + i); // 해당 가상주소의 물리주소를 얻음
    if(pa == 0) // 페이지가 매핑되어 있지 않다면 패닉 (uvmalloc에서 이미 매핑했어야 함)
      panic("loadseg: address should exist");
    
    if(sz - i < PGSIZE) // 남은 크기가 PGSIZE보다 작으면 그만큼만 읽음
      n = sz - i;
    else
      n = PGSIZE;
      
    if(readi(ip, 0, (uint64)pa, offset+i, n) != n) // 물리주소 pa에 파일 내용을 읽어들임
      return -1;
  }
  
  return 0;
}