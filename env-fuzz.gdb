echo [env-fuzz]: Init GDB...\n
handle SIGSYS nostop noprint
handle SIGSTOP nostop noprint
catch signal SIGSEGV
commands
 if $_siginfo.si_code > 32
  echo [env-fuzz]: Benign cpuid/rdtsc SEGV...Ignoring.
  continue
 end
end
echo [env-fuzz]: Init GDB...Done.\n
echo [env-fuzz]: Type "c" to run the test case.\n\n
