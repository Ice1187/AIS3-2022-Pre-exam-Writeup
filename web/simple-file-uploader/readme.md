1. It first checks that the file extension cannot be `php`, `php2`, `php3`, `php4`, `php5`, `php6`, `phar`, `phtm`, if I remember correctly. We can use `pHP` with uppercase to bypass the check, suggested by [HackTricks -- File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload#bypass-file-extensions-checks)

2. Then it checks a lot of dangerous functions. We can use backquote ``` to execute shell command. RCE!
