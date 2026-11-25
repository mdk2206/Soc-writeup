# BRabbit Lab
## 1. Bối cảnh

Bài Lab mô phỏng một vụ tấn công ransomware nhắm vào Drumbo, một công ty vừa trở thành nạn nhân. Cuộc tấn công bắt đầu khi một nhân viên nhận được email có vẻ như do cấp trên gửi, kèm logo công ty và địa chỉ email quen thuộc. Tin rằng email là thật, nhân viên đã mở tệp đính kèm, khiến hệ thống bị xâm nhập và ransomware được triển khai để mã hóa các file nhạy cảm.

Nhiệm vụ của mình là đóng vai chuyên viên điều tra: dựng lại chuỗi tấn công của ransomware Bad Rabbit bằng cách phân tích email phishing, cơ chế persistence và việc sửa đổi MBR thông qua phân tích động và khung MITRE ATT&CK, từ đó thu thập thông tin về kẻ tấn công. Công cụ sử dụng trong bài: Malpedia, VirusTotal, ANY.RUN, Email Header Analyzer, MalwareURL.

## 2. Điều tra

### Q1: The phishing email used to deliver the malicious attachment showed several indicators of a potential social engineering attempt. Recognizing these indicators can help identify similar threats in the future.
What is the suspicious email address that sent the attachment?

- Mình mở tệp `Urget Contract Action.eml` bằng Notepad để kiểm tra. Tại các trường `From:`, `Sender:` và tham số `i=` trong `DKIM-Signature:`, ghi nhận địa chỉ gửi là `theceojamessmith@Drurnbo.com` (kèm tên hiển thị Base64 `=?utf-8?B?RHJ1bWJvwq4=?=` giải mã thành `Drumbo®`).

<img width="1192" height="130" alt="image" src="https://github.com/user-attachments/assets/5f42b5a7-b168-423c-b1a0-5d49e5a8a272" />

- Đối chiếu với địa chỉ người nhận hợp lệ của công ty (`Rafaiel@Drumbo.com`), mình phát hiện kỹ thuật giả mạo tên miền gần giống: kẻ tấn công thay chữ `m` trong `Drumbo.com` bằng cặp ký tự `rn` thành `Drurnbo.com`.

- Kết luận: Địa chỉ email đáng ngờ đã gửi tệp đính kèm độc hại là `theceojamessmith@Drurnbo.com`.

### Q2: The ransomware was identified as part of a known malware family. Determining its family name can provide critical insights into its behavior and remediation strategies.
What is the family name of the ransomware identified during the investigation?

- Tại `Urget Contract Action.eml` mình tiếp tục ghi nhận tệp đính kèm có tên `Urgent Contract Action.pdf.exe` với chuỗi Base64 mở đầu bằng `TVqQ...` (chữ ký `MZ` đặc trưng của tệp thực thi Windows PE).

<img width="792" height="702" alt="image" src="https://github.com/user-attachments/assets/97841d35-5264-44e1-8c0e-3a30a3f62c70" />

- Sau đó mình đưa chuỗi base64 vào công cụ `CyberChef` để tiến hành giải mã cũng như lấy mã băm SHA-256.

<img width="1547" height="538" alt="image" src="https://github.com/user-attachments/assets/89b2803d-56d6-4b17-a4d8-c502daec3723" />

- Từ mã hash thu được mình tiến hành tra cứu trên VirusTotal.

<img width="1917" height="745" alt="image" src="https://github.com/user-attachments/assets/d238e021-0c14-4623-b0c4-bd64fe7808ae" />

-  Tại mục `Popular threat label` (`trojan.badrabbit/diskcoder`), `Family labels` mình xác nhận mẫu mã độc thuộc họ ransomware `Bad Rabbit`.

### Q3: Upon execution, the ransomware dropped a file onto the compromised system to initiate its payload. Identifying this file is essential for understanding its infection process.
What is the name of the first file dropped by the ransomware?

- Tại kết quả tra cứu trên `VirusTotal`, mình kiểm tra thông tin tại mục `Code insights` cùng danh sách tệp khởi tạo tại `BEHAVIOR (Files Written)` và `RELATIONS (Dropped Files)`..

<img width="1766" height="127" alt="image" src="https://github.com/user-attachments/assets/746a336d-eba6-49c8-b58d-4c28f523b1cb" />

- Kết quả ghi nhận ngay khi thực thi, tệp dropper trích xuất phần dữ liệu nhúng (*overlay*) bên trong tệp thực thi PE, giải mã bằng khóa XOR `0xE9` và giải nén qua thư viện `zlib`. Dữ liệu giải nén được ghi xuống hệ thống dưới dạng một tệp DLL ngụy trang đuôi `.dat` tại đường dẫn `C:\Windows\infpub.dat`, sau đó được kích hoạt ngầm thông qua tiến trình hợp pháp của Windows bằng câu lệnh:`rundll32.exe C:\Windows\infpub.dat,#1`.

### Q4: Inside the dropped file, the malware contained hardcoded artifacts, including usernames and passwords that could provide clues about its origins or configuration.
What is the only person's username found within the dropped file?

- Từ trang phân tích của tệp dropper trên `VirusTotal1 (SHA-256: 630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da)`, mình chuyển sang tab `RELATIONS → mục Dropped Files `để truy cập hồ sơ của tệp payload đầu tiên `infpub.dat (SHA-256: 579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648)`.

<img width="1851" height="345" alt="image" src="https://github.com/user-attachments/assets/73aa7683-62af-41c0-9981-8fa2f94413b5" />


- Sau đó từ hash này của `infput.dat` mình tra cứu thông tin các bài báo cáo của nó thì phát hiện được một danh sách từ điển tên đăng nhập và mật khẩu nhúng cứng phục vụ hành vi tấn công dò mật khẩu, `alex` là tên riêng cá nhân có mặt trong danh sách này.

### Q5: After execution, the ransomware communicated with a C2 server. Recognizing its communication techniques can assist in mitigation.
What MITRE ATT&CK sub-technique describes the ransomware’s use of web protocols for sending and receiving data?

- ở tab `BEHAVIOR` của mẫu `infpub.dat` trên VirusTotal, tại mục `MITRE ATT&CK Tactics and Techniques` dưới nhóm chiến thuật `Command and Control (`TA0011`)`, hành vi lợi dụng giao thức tầng ứng dụng để ngụy trang kênh liên lạc C2 được xếp vào kỹ thuật chính `Application Layer Protocol (T1071)`.

<img width="1785" height="547" alt="image" src="https://github.com/user-attachments/assets/905a3ad6-7e2a-43a2-9c02-d2b8ccc6b820" />

- Sau đó mình tra cứu chi tiết phân cấp của `T1071` trên cơ sở dữ liệu MITRE ATT&CK Enterprise, kỹ thuật con mô tả việc sử dụng các giao thức web (HTTP/HTTPS/WebDAV) để gửi và nhận dữ liệu có mã `T1071.001` với tên gọi chuẩn là `Web Protocols`.

### Q6: Persistence mechanisms are a hallmark of sophisticated ransomware. Identifying how persistence was achieved can aid in recovery and prevention of reinfection.
What is the MITRE ATT&CK Sub-Technique ID associated with the ransomware’s persistence technique?

- Trên `VirusTotal`, tại tab `BEHAVIOR` mình kiểm tra ma trận MITRE ATT&CK Tactics and Techniques, tại nhóm Persistence -> Scheduled Task/Job (`T1053`) và chọn kỹ thuật con `Scheduled Task` mang mã là `(T1053.005)`.

<img width="1750" height="806" alt="image" src="https://github.com/user-attachments/assets/95719831-4383-4334-aff7-fe76301a0f87" />


