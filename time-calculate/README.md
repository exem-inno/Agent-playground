# bpf-example
__eBPF with Go__

BPF 프로그램을 만드는 가장 흔한 방법은 C 언어로 소스 코드를 작성하고 그것을 LLVM으로 컴파일하는 것이다.
LLVM은 다양한 종류의 바이트코드를 산출할 수 있는 범용 컴파일러이며, Clang은 LLVM의 메인 프론트엔드이다.
LLVM을 통해 BPF 프로그램을 컴파일해서 유효한 ELF 이진 파일(리눅스 커널이 적재할 수 있는 이진 실행 파일 형식)을 만들고 커널에 적재하는 일련의 과정을 진행하고 정리해보자.

[cilium/ebpf](https://github.com/cilium/ebpf)를 사용해 eBPF 프로그램을 작성하고 컴파일하고, 커널에 적재하고자 한다.

## eBPF Program

cilium/ebpf를 사용할 때 eBPF Program은 C 언어로 작성해도 되고, Go 언어 내부에서 BPF 어셈블리 코드를 사용해 프로그램을 작성해도 된다.
여기에서는 가장 보편적인 방법인 C 언어로 Program을 작성하는 방법을 분석해 보고자 한다.
`/src/bpf/execve.c`에 정의된 코드이다.

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry *args)
{
  struct event info = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  info.pid = pid_tgid & 0xFFFFFFFF;

  bpf_probe_read_user_str(info.fname, sizeof(info.fname), args->filename);

  bpf_get_current_comm(info.comm, sizeof(info.comm));

  bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));

  bpf_printk("hello, world\n");

  return 0;
}

```

이 코드를 통해 BPF VM이 해당 프로그램을 실행할 시점을 정의한다.
구체적으로 보자면, 이 예제는 execve 시스템 호출의 추적점(tracepoint)이 검출되었을 때 BPF VM이 이 BPF 프로그램을 실행해야 함을 SEC 매크로로 지정한다.
추적점은 커널의 이진 코드 안에 있는 정적 표식(mark)이다. BPF 프로그램 개발자는 실행 추적이나 디버깅을 위해 추적점에 임의의 코드를 주입할 수 있다.
커널에 미리 정의해둔 추적점들에만 코드를 붙일 수 있다는 점에서 kprobe 프로그램보다 덜 유연하지만, 일단 정의되고 나면 변하지 않으므로 안정적이다.

시스템의 모든 추적점은 /sys/kernel/debug/tracing/events 아래에 정의되어 있다.

코드를 하나하나 살펴보자.

`bpf_get_current_pid_tgid()`
: tgid 및 pid를 포함하는 64비트 정수(`current_task->tgid << 32 | current_task->pid`)가 반환된다.
현재로썬 pid만 필요하므로 last 32 bit만 가져와서 pid를 얻고 이를 info.pid에 채운다.

`bpf_probe_read_user_str(info.fname, sizeof(info.fname), args->filename);`
: 안전하지 않은 사용자 주소인 unsafe_ptr(`args->filename`)에서 dst(`info.comm`)로 문자열을 복사한다.
size에는 NUL 바이트가 포함되어 있어야 하며 성공하면 복사된 문자열의 길이가 반한된다. `bpf_probe_read_user()` helper를 사용하여 문자열을 읽을 수도 있지만, 컴파일 시간에 길이를 추정해야 하며 간혹 필요한 것보다 더 많은 메모리를 복사하게 될 수도 있다.

`bpf_get_current_comm(info.comm, sizeof(info.comm));`
: 현재 task의 comm 속성을 buf(`info.comm`)에 복사한다. comm 속성에는 현재 task의 실행 파일 이름(경로 제외)이 포함된다.

`bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));`
: `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 타입의 map(`&events`)이 보유하는 BPF perf event에 raw data(`&info`) blob을 쓴다.
이 perf event는 PERF_SAMPLE_RAW를 sample_type으로, PERF_TYPE_SOFTWARE를 type으로, PERF_COUNT_SW_BPF_OUTPUT을 config로 지정해야 한다.
flag는 값을 넣어야하는 map(`&events`)의 인덱스를 나타내는데 사용되며 BPF_F_INDEX_MASK로 마스킹된다.
flag를 `BPF_F_CURRENT_CPU`로 설정하여 현재 CPU 코어의 인덱스를 사용해야 함을 나타낼 수 있다.

`bpf_printk("hello, world\n");`
: 추적 파이프에 대한 간편한 측정을 위해 hello, world 출력한다.
`bpf_printk`는 내부적으로 `bpf_trace_printk` helper를 호출하는데, 이는 디버깅을 위한 printk()-like 기능이다.
사용 가능한 경우 DebugFS에서 /sys/kernel/debug/tracing/trace 파일에 정의된 메시지를 출력한다.
만약 `/sys/kernel/debug/tracing/trace`가 열려 있는 동안엔 메시지는 삭제된다.
이를 방지하려면 `/sys/kernel/debug/tracing/trace_pipe`를 사용하면 된다.

### Parameter

이제 해당 함수의 파라미터로 사용 중인 `execve_entry` 구조체를 확인해보자.

```c
struct execve_entry {
  u64 _unused;
  u64 _unused2;

  const char* filename;
  const char* const* argv;
  const char* const* envp;
};
```

이 프로그램에서 사용할 커스텀한 추적 이벤트 객체를 만든다.
아래에서 해당 추적 지점에 대해 얻을 수 있는 모든 정보가 표시된다.

```shell
❯ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format

name: sys_enter_execve
ID: 707
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
```

우리가 원하는 정보는 filename 이후의 정보이다.
filename 필드의 offset이 16 byte이므로 128 bit부터 유의미한 데이터가 되므로 u64 타입의 unused 필드를 사용해 구조를 맞춘다.

### BPF Map

BPF 맵은 커널 안에 존재하는 Key-Value 저장소이며 그 위치를 아는 모든 BPF 프로그램이 접근할 수 있다.
사용자 공간에서 실행되는 프로그램도 특정 파일 서술자를 이용해서 접근이 가능하다.

BPF 맵에는 그 어떤 형식의 자료도 저장할 수 있다. 단, 저장 전에 자료의 크기를 명시할 수 있어야 한다.
커널은 키와 값을 이진 blob으로 취급할 뿐, 그 안에 담긴 내용과 형식이 무엇인지는 신경 쓰지 않는다.

```c
struct bpf_map_def SEC("maps") events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
};
```

프로그램에 필요한 맵의 유형을 미리 알고 있다면 위와 같이 맵을 사전에 정의해둘 수 있으며,
`SEC("maps")` 섹션 특성(section attribute)를 사용해 이 구조체가 하나의 BPF 맵임을 커널에 알릴 수 있게 된다.

### Event

바로 위에서 언급한 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 타입의 map(`&events`)이 보유하는 BPF perf event에 쓸 raw data를 정의한다.

```c
struct event {
  u32 pid;
  u8 fname[32];
  u8 comm[32];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));
```

`const struct event *unused __attribute__((unused));`
: 위 event 구조체는 이 BPF 프로그램을 컴파일하고 커널에 적재하고 이후의 작업을 처리할 .go 파일에서도 동일한 포맷으로 정의가 되고 사용이 되어야 한다.
위 코드를 사용하게 되면 `bpf2go`를 통해 프로그램이 컴파일될 때 해당 event 구조체도 자동으로 알아서 bpfel.go 파일에 반영이 된다.
이는 `github.com/cilium/ebpf` 의존성의 _v0.8.2-0.20220217141816-62da0a730ab7_ 버전부터 지원되는 기능으로 확인이 되니 참고하여 사용하도록 하자.

## main.go

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event bpf ./bpf/execve.c -- -I/usr/include/bpf -I./headers
```

`go:generate` marker를 통해 bpf2go를 실행하도록 지시한다.
bpf2go는 clang을 통해 `./bpf/execve.c`에 작성된 BPF 프로그램을 컴파일하고 `bpf_bpfel.o`, `bpf_bpfel.go` 파일을 생성한다.
여기에서 생성된 `bpf_bpfel.go` 파일은 main.go를 쉽게 작성할 수 있도록 도움을 준다.

```go
func main() {
  // Subscribe to signals for terminating the program.
  stopper := make(chan os.Signal, 1)
  signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

  // Allow the current process to lock memory for eBPF resources.
  if err := rlimit.RemoveMemlock(); err != nil {
    log.Fatal(err)
  }

  // Load pre-compiled programs and maps into the kernel.
  objs := bpfObjects{}
  if err := loadBpfObjects(&objs, nil); err != nil {
    log.Fatalf("loading objects: %v", err)
  }
  defer objs.Close()

  // Open a Tracepoint at the entry point of the kernel function and attach the pre-compiled program.
  tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)
  if err != nil {
    log.Fatalf("opening tracepoint: %s", err)
  }
  defer tp.Close()

  // Open a perf reader from userspace PERP map described in the eBPF C program.
  rd, err := perf.NewReader(objs.Events, os.Getpagesize())
  if err != nil {
    log.Fatalf("opening perf reader: %s", err)
  }
  defer rd.Close()

  // Close the reader when the process receives a signal, which will exit the read loop.
  go func() {
    <-stopper

    if err := rd.Close(); err != nil {
      log.Fatalf("closing perf reader: %s", err)
    }
  }()

  log.Println("waiting for events..")

  // bpfEvent is generated by bpf2go.
  var event bpfEvent
  for {
    record, err := rd.Read()
    if err != nil {
      if errors.Is(err, perf.ErrClosed) {
        log.Println("received signal, exiting..")
        return
      }
      log.Printf("reading from reader: %s", err)
      continue
    }

    if record.LostSamples != 0 {
      log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
      continue
    }

    // Parse the perf event entry into a bpfEvent structure.
    if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
      log.Printf("parsing perf event: %s", err)
      continue
    }

    fmt.Printf("On cpu %02d %s ran : %d %s\n", record.CPU, event.Comm, event.Pid, event.Fname)
  }
}
```

`signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)`
: 프로그램의 종료 신호를 구독한다.

`rlimit.RemoveMemlock()`
: 현재 프로세스가 eBPF 리소스에 대한 메모리를 잠글 수 있도록(lock) 허용한다.
RemoveMemlock은 필요한 경우 현재 프로세스가 RAM에 잠글 수 있는 메모리 양에 대한 제한을 제거한다.
cgroup-based memory accounting의 도입으로 인해 커널 버전 5.11부터는 eBPF 리소스를 로드하는데 이 기능을 필요로 하지 않는다.
이 기능은 편의상 존재하며 영구적으로 RLIMIT_MEMLOCK을 무한으로 올리는 것이 적절한 경우에만 사용해야 한다.
원하는 경우 보다 합리적인 제한으로 prlimit(2)를 직접 호출하는 것을 고려하자.

`loadBpfObjects(&objs, nil)`
: pre-compiled program과 map을 커널에 로드한다.

`tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)`
: tracepoint를 열고 pre-compiled program을 연결한다.
커널 함수가 입력될 때마다 프로그램은 perf buffer에 지정된 perf event를 기록한다.
처음 두 arguments는 `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve` 경로에서 가져오면 된다.

`rd, err := perf.NewReader(objs.Events, os.Getpagesize())`
: eBPF C 프로그램에서 설명된 userspace PERF 맵으로부터 perf reader를 가져온다.

`go func() {`
: 프로세스가 신호를 수신하게 되면 reader를 닫고 read loop도 종료하게 된다.

`var event bpfEvent`
: bpfEvent 구조체는 bpf2go에 의해 생성된다.

`binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)`
: perf event entry를 bpfEvent 구조로 변환한다.
x86은 little endian machine이므로 byte order를 그에 맞게 지정해주자.

## How to use

```shell
➜  bpf-example git:(main) make
go generate src/*.go
Compiled /home/parallels/Workspace/bpf-example/src/bpf_bpfel.o
Stripped /home/parallels/Workspace/bpf-example/src/bpf_bpfel.o
Wrote /home/parallels/Workspace/bpf-example/src/bpf_bpfel.go
CGO_ENABLED=0 go build -o exec_scrape src/*.go
```

Makefile을 실행하면 exec_scrape 파일이 생성된다.
이를 통해 작성했던 BPF 프로그램을 실제로 실행할 수 있게 된다.

```shell
➜  bpf-example git:(main) sudo ./exec_scrape
2022/03/25 00:59:26 waiting for events..
On cpu 00 prlshprint ran : 118136 /bin/sh
On cpu 00 sh ran : 118138 /usr/bin/sed
On cpu 01 sh ran : 118137 /usr/bin/lpstat
On cpu 00 prlshprint ran : 118139 /bin/sh
On cpu 00 sh ran : 118141 /usr/bin/lpstat
On cpu 01 sh ran : 118142 /usr/bin/sed
On cpu 01 prlshprint ran : 118143 /bin/sh
On cpu 00 sh ran : 118144 /usr/bin/lpstat
On cpu 01 sh ran : 118145 /usr/bin/sed
2022/03/25 00:59:30 received signal, exiting..
```

실행하면 위와 같이 execve 시스템 호출의 추적점을 통해 한 프로그램이 다른 프로그램을 실행하는 상황이 커널에 포착될 때의 이벤트가 출력되는 것을 확인할 수 있다.

```shell
      prlshprint-118136  [000] d... 16371.756553: bpf_trace_printk: hello, world
          lpstat-118137  [001] d... 16371.757808: bpf_trace_printk: hello, world
             sed-118138  [000] d... 16371.757899: bpf_trace_printk: hello, world
      prlshprint-118139  [000] d... 16372.824015: bpf_trace_printk: hello, world
          lpstat-118141  [000] d... 16372.825758: bpf_trace_printk: hello, world
             sed-118142  [001] d... 16372.826010: bpf_trace_printk: hello, world
      prlshprint-118143  [001] d... 16374.093667: bpf_trace_printk: hello, world
          lpstat-118144  [000] d... 16374.095143: bpf_trace_printk: hello, world
             sed-118145  [001] d... 16374.095145: bpf_trace_printk: hello, world
```

`/sys/kernel/debug/tracing/trace`에서 `/src/bpf/execve.c`의 마지막 부분에 출력하도록 했던 hello, world 메시지도 볼 수 있다.
