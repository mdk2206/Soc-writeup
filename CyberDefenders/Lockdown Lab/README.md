# Lockdown Lab
## 1. Bối cảnh
Bài Lab mô phỏng một sự cố tại TechNova Systems. Đội SOC phát hiện lưu lượng ra ngoài đáng ngờ từ một máy chủ IIS công khai trên nền tảng đám mây, có dấu hiệu của việc thả web shell và thiết lập các kết nối ngầm tới một máy chủ lạ.

Đội ứng cứu thu thập ba artifact: một file PCAP ghi lại lưu lượng ban đầu, một bản memory image đầy đủ của máy chủ và một mẫu mã độc được thu hồi từ đĩa.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra số: phân tích lần lượt ba artifact để dựng lại toàn bộ chuỗi xâm nhập và hoạt động của kẻ tấn công, gồm cách thức xâm nhập ban đầu, web shell được thả xuống, các tiến trình và kết nối mạng độc hại, cùng đặc điểm của mẫu mã độc, từ đó trích xuất các IOCs để TechNova ngăn chặn sự cố và củng cố phòng thủ.

## 2. Điều tra
### Q1: After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?
- Mình mở file PCAP bằng Wireshark và dùng Statistics → Conversations → IPv4 để phân tích. Máy chủ IIS là `10.0.2.15`, trong các cặp được xuất hiện, cặp `10.0.2.4` - `10.0.2.15` có lưu lượng lớn nhất: 6.007 gói, trong khi các cặp khác chỉ từ 2 đến 52 gói.

 <img width="1831" height="466" alt="image" src="https://github.com/user-attachments/assets/8fc99181-67e0-4a56-8c04-a7a3a6bc6782" />

 **Đáp án:** `10.0.2.4`

 ### Q2: The attacker is carrying out targeted enumeration against the HTTP service on the IIS host. Based on the HTTP request headers, which tool is being used?
 - Mình lọc các request HTTP do `10.0.2.4` gửi tới máy chủ IIS bằng `http.request && ip.src == 10.0.2.4` và kiểm tra header của từng gói. Ở gói 2140 mình phát hiện được trường User-Agent ghi `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`.

<img width="1467" height="697" alt="image" src="https://github.com/user-attachments/assets/03893774-74ff-4280-af9f-aaa273d07099" />

- User-Agent này cho thấy kẻ tấn công dùng **Nmap** với Nmap Scripting Engine để liệt kê dịch vụ HTTP.
**Đáp án:** `Nmap`

### Q3: While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?
- Mình sẽ lọc các yêu cầu Tree Connect của SMB2 bằng `smb2.cmd == 3 && smb2.flags.response == 0 && ip.src == 10.0.2.4` và bắt được 3 gói tin.

<img width="1917" height="287" alt="image" src="https://github.com/user-attachments/assets/86466e71-c225-42e5-9a8e-e292f2fdfd68" />

- Hai yêu cầu Tree Connect liên tiếp từ `10.0.2.4` tới `10.0.2.15:445` là gói 2672 với đường dẫn **\\10.0.2.15\IPC$** và gói 2678 với đường dẫn **\\10.0.2.15\Documents**. Đây là hai share đầu tiên kẻ tấn công dò trên máy chủ IIS. `IPC$` là share dùng cho giao tiếp named pipe, còn `Documents` là share chứa dữ liệu của người dùng.

<img width="1435" height="627" alt="image" src="https://github.com/user-attachments/assets/208f5810-4a0a-4acc-b24c-ea0dc6e873f3" />

<img width="1430" height="652" alt="image" src="https://github.com/user-attachments/assets/fe8cc52a-c2eb-48a1-abfc-0d767883adb4" />

**Đáp án:** `\\10.0.2.15\IPC$`, `\\10.0.2.15\Documents`

### Q4: Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded?

- Mình lọc các lệnh ghi dữ liệu của SMB2 do kẻ tấn công gửi bằng `smb2.cmd == 9 && ip.src == 10.0.2.4`, thêm trường `Filename` làm cột. Kết quả chỉ có một gói Write (gói 3505, tại giây 342,6, đích `10.0.2.15:445`), ghi vào file **shell.aspx**

<img width="1917" height="300" alt="image" src="https://github.com/user-attachments/assets/6b8039d2-acbb-4267-9eeb-32b8e75b7b94" />

**Đáp án:** `shell.aspx`

### Q5: The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?

- Sau khi `shell.aspx` được ghi lên máy chủ (gói 3505, giây 342,6), mình lọc các kết nối do máy chủ chủ động mở ra tới kẻ tấn công bằng `ip.src == 10.0.2.15 && ip.dst == 10.0.2.4 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && frame.number > 3505`.

<img width="1917" height="332" alt="image" src="https://github.com/user-attachments/assets/97370ff7-fb3a-427c-8620-bc5ed99658e8" />

- Kết quả có đúng một gói SYN (gói 3585, giây 401,5) từ `10.0.2.15` (cổng nguồn 49688) tới `10.0.2.4`, cổng đích **4443**. Máy chủ chủ động kết nối ra ngoài, nên `10.0.2.4` đang lắng nghe ở cổng 4443, đây chính là kết nối reverse shell.

<img width="1557" height="513" alt="image" src="https://github.com/user-attachments/assets/58cfb4e8-9194-4383-9fdc-88bf0726f0d2" />

**Đáp án:** `4443`

### Q6: Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?
- Mình dùng plugin `windows.info` của Volatility 3 để lấy thông tin hệ thống từ memory image: `vol3 -f memdump.mem windows.info`.

<img width="1050" height="480" alt="image" src="https://github.com/user-attachments/assets/1f7971c3-114b-4aff-bc78-7beb91cc455e" />

- Dòng `Kernel Base` cho thấy địa chỉ nạp của kernel là **0xf80079213000**

**Đáp án:** `0xf80079213000`

### Q7: A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable?
- Mình dùng plugin `windows.pslist` của Volatility 3 để liệt kê tiến trình từ memory dump và thấy tiến trình lạ **updatenow.exe** (PID 4900), tên này không thuộc các tiến trình chuẩn của Windows Server hay IIS nên mình chọn để điều tra tiếp.

<img width="1337" height="412" alt="image" src="https://github.com/user-attachments/assets/9cb84523-87db-47c8-b9a5-2047b79ec1d3" />

- Mình tiếp tục quét memory image bằng `windows.filescan` kết hợp tìm "updatenow.exe" trong kết quả: `vol3 -f memdump.mem windows.filescan | grep -i updatenow`. Đường dẫn trên đĩa là **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updatenow.exe**.

<img width="870" height="96" alt="image" src="https://github.com/user-attachments/assets/7dfd65a9-2478-4238-b912-454fbeac1b5c" />

**Đáp án:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updatenow.exe`

### Q8: The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?

- Mình lọc `windows.netscan` bằng `grep -E "4443|10.0.2.4"` và thấy kết nối TCPv4 từ `10.0.2.15:49688` tới `10.0.2.4:4443` ở trạng thái CLOSED, cổng nguồn khớp gói SYN trong pcap. Tiến trình sở hữu kết nối là **w3wp.exe** (PID **4332**).

<img width="1271" height="113" alt="image" src="https://github.com/user-attachments/assets/55f30876-c533-4e0b-8e3f-25c054ea300f" />

- Sau đó mình tiếp tục dùng `windows.pstree` để xem quan hệ cha-con thì phát hiện: `svchost.exe -k iissvcs` (PID 2452) sinh ra `w3wp.exe` (PID 4332), và `w3wp.exe` sinh ra `updatenow.exe` (PID 900, PPID 4332).

<img width="1668" height="316" alt="image" src="https://github.com/user-attachments/assets/3aadacce-6477-4e29-88a3-6620ab644f27" />

**Đáp án:** `w3wp.exe`, `4332`
