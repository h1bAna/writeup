int __cdecl main(int argc, const char **argv, const char **envp)
{
  signal(14, timeout);
  alarm(0x3Cu);
  memset(&myCart, 0, 0x10u);
  menu();
  return handler();
}