# csgo-load-library-bypass-injector
A non-byte patching bypass for CS:GO's LoadLibrary injection prevention system.

# Information
CS:GO hooks NtOpenFile (ntdll.dll) from within csgo.exe.

The hooked NtOpenFile looks somewhat like this:
```
int __stdcall NtOpenFileHk(int a1, int a2, int a3, int a4, int a5, int a6)
{
  int result; // eax

  if ( *(_DWORD *)(*(_DWORD *)(a3 + 8) + 4) && a2 & 0x20 && !IsTrustedModule(*(wchar_t **)(*(_DWORD *)(a3 + 8) + 4)) )
    result = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
  else
    result = OriginalNtOpenFile(a1, a2, a3, a4, a5, a6);
  return result;
}
```
It first runs some checks, and then returns STATUS_OBJECT_NAME_NOT_FOUND resulting in LoadLibrary failing.
If we can somehow make IsTrustedModule return true, it will instead call the original NtOpenFile function making the LoadLibrary succeed.

Inside of IsTrustedModule, there's a check like this:
```
if ( !dword_4748FC || dword_474900 > dword_4748FC )
    return 1;
```
Meaning, if we either set dword_4748FC to 0, or dword_474900 higher than dword_4748FC, it will return true.
However, looking at references to them, they are used as some kind of index and highest index of some trust routine which will check if there hasn't 
been done any tampering with CS:GO files. (csgo.signatures, steam.signatures etc..).
If we just set dword_4748FC to 0, or set dword_474900 higher than dword_4748FC, when joining a game, you'll receive an error saying there has been done tampering with CS:GO's files.

# Bypassing
We've figured out what can be done in order to bypass the LoadLibrary injection prevention system, however we also found a culprit.
The bypass that is being used here is setting dword_474900 higher than dword_4748FC. dword_4748FC should be 4 (at the time of writing this) so we simply set dword_474900 to 5.
After that, we continue normal LoadLibrary injection, and after that's been done we restore dword_474900's value, by setting it to the backed up value.
By quickly restoring the value, we wont receive an error when we're trying to join a VAC secured server.
