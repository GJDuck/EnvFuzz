Program Environment Fuzzing
===========================

Computer programs are not executed in isolation, but rather interact with a
(possibly complex) environment which drives the program's behaviour.
Traditional fuzzers, such as AFL and AFLNet, only target specific inputs from
the overall environment, such as `stdin` or a specified socket.
The *Program Environment Fuzzer* (EFuzz) is a new fuzzer that design that
specifically targets the "full" environment, including all inputs regardless
of source or type (file, sockets, devices, etc.)

EFuzz is very powerful, and can fuzz most off-the-shelf binary code with zero
set-up.
EFuzz is very general, and can fuzz a diverse range of applications, such a
file processing, compilers, data-bases, network servers/clients, GUI
applications, text editors, system utilities, development tools, multimedia
applications, etc.

EFuzz is built on top of a full environmental *Record and Replay*
infrastructure (RRFuzz).
Basically, the infrastructure supports two main phases:

1. *Record* Phase: Executes the program normally, but sniffs and records all
environmental interactions (e.g., system calls) into a special PCAP file.
2. *Replay and Fuzz* Phase: Executes the program again, one or more times.
This time, environmental interactions are *replayed* from the PCAP file, rather
than interacting with the real environment.
However, instead of replaying the interactions exactly, the RRFuzz framework
applies *mutation operators* to induce new program behaviours, and possibly
cause program misbehaviour including crashes.

Since EFuzz+RRFuzz works at the abstraction of system calls, it can fuzz a
diverse range of programs without any special handling.

More information and the source code is coming soon.

Preprint
--------

* Ruijie Meng, Gregory J. Duck, Abhik Roychoudhury, [*Program Environment Fuzzing*](https://arxiv.org/abs/2404.13951), 2024

