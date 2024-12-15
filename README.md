# fuzzmap
Web Application Offensive Fuzzing Module

ex 1)
from fuzzmap import sqli
sqli = SQLInjection(target, "be", headers=headers, cookies=cookies)
result = sqli.run()

print(result)



result:
http://testphp.vulnweb.com, blind & error sql injection attack success - payload: ' or 1=1 -- -

ex 2)
from fuzzmap import sqli, all
all_attack = webfuzz(target, headers=headers, cookies=cookies)
result = all_attack.run()

print(result)


result:
http://testphp.vulnweb.com
[+] INFO: sqli - payload ...
[+] INFO: xss - payload ...
[+] INFO: csrf - payload ...
[+] INFO: lfi - payload ...

공격 방식:
전체 엔드포인트, 일부 엔드포인트, 입력한 타겟 엔드포인트만 공격 (방식 고민 중)

모듈 특징: 외부 도구 또는 설정이 많이 필요한 모듈 사용 X (직접 만들어야 함)
-> requests (O) - requests는 괜찮음
-> dirsearch (X)
-> nmap (X)