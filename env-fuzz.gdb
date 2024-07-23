handle SIGSYS nostop noprint
handle SIGSTOP nostop noprint
catch signal SIGSEGV
commands
 if $_siginfo.si_code > 2
  continue
 end
end
continue
