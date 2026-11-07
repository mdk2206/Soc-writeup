# BlueSky Ransomeware Lab
## 1. Bối cảnh
Bài Lab mô phỏng một sự cố an ninh nghiêm trọng tại một tập đoàn quản lý dữ liệu và dịch vụ quan trọng cho nhiều ngành. Mạng của tổ chức nghi bị tấn công bằng ransomware: các file quan trọng bị mã hóa gây gián đoạn hoạt động, đồng thời làm dấy lên lo ngại dữ liệu có thể đã bị đánh cắp. Dấu hiệu ban đầu cho thấy sự tham gia của một tác nhân đe dọa có trình độ cao.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra: phân tích các bằng chứng được cung cấp để xác định phương pháp xâm nhập của kẻ tấn công, đánh giá phạm vi của vụ xâm phạm, từ đó trích xuất các IOCs và đề xuất hướng khoanh vùng để khôi phục tính toàn vẹn của mạng.

## 2. Điều tra

### Q1: Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?
- Mình mở file PCAP bằng Wireshark và dùng Statistics → Conversations → IPv4. Mình phát hiện thấy hai địa chỉ `87.96.21.81` và `87.96.21.84` trao đổi 4.767 gói (2 MB) trong khoảng 151 giây, cho thấy rất nhiều kết nối ngắn. Các dòng còn lại chỉ là lưu lượng gửi tới địa chỉ multicast `239.255.255.250`.

<img width="1593" height="228" alt="image" src="https://github.com/user-attachments/assets/55fde852-b31f-4cc9-98e2-5a8100720a9d" />

- Mình lọc `tcp.flags.syn == 1 && tcp.flags.ack == 0` để xem các gói mở kết nối. Toàn bộ gói SYN đi từ `87.96.21.84` tới `87.96.21.81`, mỗi gói nhắm một cổng đích khác nhau (80, 443, 5900,...). Đây là hành vi quét cổng nên mình kết luận đáp án là `87.96.21.84`

### Q2: During the investigation, it's essential to determine the account targeted by the attacker. Can you identify the targeted account username?
- Mình sẽ sử dụng bộ lọc giao thức tds để thu hẹp các gói tin tương tác với dịch vụ cơ sở dữ liệu Microsoft SQL Server.
- Sau đó mình quan sát ở cột Info và tìm đến các gói tin mang nhãn TDS7 login chứa yêu cầu xác thực đăng nhập từ máy tấn công.

<img width="1917" height="537" alt="image" src="https://github.com/user-attachments/assets/173202f0-3c7e-4764-b337-62238ee6ed96" />

- Mình mở rộng cây chi tiết gói tin ở khung bên dưới, kiểm tra phần thông tin cấu trúc giao thức TDS để đọc các trường dữ liệu đăng nhập và phát hiện user là `sa`

<img width="585" height="377" alt="image" src="https://github.com/user-attachments/assets/c7589747-c589-49a9-adc6-05debd48a62d" />

### Q3: We need to determine if the attacker succeeded in gaining access. Can you provide the correct password discovered by the attacker?

- Cũng từ kết quả của câu 2 thì mình tìm được password là ` cyb3rd3f3nd3r$`

### Q4: Attackers often change some settings to facilitate lateral movement within a network. What setting did the attacker enable to control the target host further and execute further commands?

- Sau khi đăng nhập thành công với quyền sa, kẻ tấn công tiến hành thay đổi cấu hình hệ thống SQL Server để chuẩn bị cho bước di chuyển ngang vì vậy mình sẽ lọc các gói tin mang nhãn SQL batch để điều tra.

- Tại gói tin Frame 2643, trong phần truy vấn TDS Query Packet, mình phát hiện kẻ tấn công đã gửi chuỗi lệnh: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`

<img width="1238" height="725" alt="image" src="https://github.com/user-attachments/assets/a7ad2781-4214-482b-ad6b-18fb05e4c2df" />

Đáp án: `xp_cmdshell`

### Q5: Process injection is often used by attackers to escalate privileges within a system. What process did the attacker inject the C2 into to gain administrative privileges?

- Để tìm hiểu tiến trình mà kẻ tấn công nhắm tới để thực hiện tiêm mã nhằm leo thang đặc quyền, mình tiến hành kiểm tra tệp nhật ký sự kiện BlueSkyRansomware.evtx và lọc nguồn sự kiện PowerShell.

- Mình tìm đến Event ID 400 ghi nhận khởi đầu của phiên bản PowerShell engine.Ở log đầu tiên mình phát hiện được trường HostName = MSFConsole (cho thấy kẻ tấn công đang sử dụng Metasploit Framework làm C2) và trường HostApplication = winlogon.exe.

- Từ các dữ liệu trên, mình xác định được kẻ tấn công đã thực hiện kỹ thuật tiêm payload Metasploit C2 vào  `winlogon.exe`'

### Q6: Following privilege escalation, the attacker attempted to download a file. Can you identify the URL of this file downloaded?

- Để tìm kiếm đường dẫn URL của tệp tin mà kẻ tấn công đã tải xuống ngay sau khi thực hiện leo thang đặc quyền thành công, mình sẽ sử dụng bộ lọc http.

- Mình quan sát thấy các gói tin HTTP GET xuất hiện trong tệp PCAP, mình nhận thấy kẻ tấn công đã phát sinh hàng loạt yêu cầu truy xuất tệp lệnh như checking.ps1, del.ps1, ichigo-lite.ps1, Invoke-PowerDump.ps1. Tuy nhiên, nội dung câu hỏi yêu cầu xác định cụ thể tệp được tải xuống ngay "Following privilege escalation" nên mình sẽ chọn gói đầu tiên là ` checking.ps1 `

<img width="1917" height="798" alt="image" src="https://github.com/user-attachments/assets/d3097c04-9bb4-4d48-8c6f-fe532b68e7e9" />

- Sau khi phân tích sâu vào gói tin thì mình thu thập được URL là ` http://87.96.21.84/checking.ps1`

<img width="932" height="582" alt="image" src="https://github.com/user-attachments/assets/677191a9-ebff-43a1-a4be-5b8556c7cae8" />

### Q7: Understanding which group Security Identifier (SID) the malicious script checks to verify the current user's privileges can provide insights into the attacker's intentions. Can you provide the specific Group SID that is being checked?

- Để tìm kiếm Security Identifier (SID) của nhóm mà tập lệnh độc hại kiểm tra nhằm xác định đặc quyền của người dùng hiện tại, mình tiến hành theo dõi luồng HTTP Stream của tệp tin checking.ps1

- Sau đó mình quan sát thấy được dòng lệnh kiểm tra đặc quyền sau ` $priv = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
$osver = ([environment]::OSVersion.Version).Major`

<img width="1411" height="365" alt="image" src="https://github.com/user-attachments/assets/1bfd90fa-0257-4eda-ac45-18d4dcd1d8dd" />

Kết quả ` S-1-5-32-544`

### Q8: Windows Defender plays a critical role in defending against cyber threats. If an attacker disables it, the system becomes more vulnerable to further attacks. What are the registry keys used by the attacker to disable Windows Defender functionalities? Provide them in the same order found.

- Để xác định các khóa registry được sử dụng nhằm vô hiệu hóa các tính năng bảo vệ của Windows Defender, mình tiếp tục phân tích nội dung mã nguồn trong luồng HTTP của checking.ps1.
- Bên dưới đoạn mã kiểm tra phân quyền hệ thống, mình thấy tệp lệnh checking.ps1 tiếp tục khai báo hàm Disable-WindowsDefender để can thiệp trực tiếp vào cấu hình bảo mật trên registry của Windows.

<img width="1102" height="567" alt="image" src="https://github.com/user-attachments/assets/94ceaa5b-21ee-4df7-94bb-475cedbe2a44" />

- Kẻ tấn công thiết lập đường dẫn registry mục tiêu và định nghĩa mảng bao gồm 5 khóa registry sau đó dùng vòng lặp foreach kết hợp lệnh Set-ItemProperty để gán giá trị 1 cho lần lượt từng khóa registry trong mảng.

Đáp án ` DisableAntiSpyware, DisableRoutinelyTakingAction, DisableRealtimeMonitoring, SubmitSamplesConsent, SpynetReporting `

### Q9: Can you determine the URL of the second file downloaded by the attacker?

- Ở câu này mình tiếp tục dùng lại kết quả của bộ lọc http, sau yêu cầu đầu tiên: GET /checking.ps1 thì yêu cầu thứ hai ngay sau đó chính là GET /del.ps1.
- Phân tích sâu yêu cầu GET /del.ps1 thì mình thu được URL là ` http://87.96.21.84/del.ps1`

### Q10: Identifying malicious tasks and understanding how they were used for persistence helps in fortifying defenses against future attacks. What's the full name of the task created by the attacker to maintain persistence?

- Ở câu này mình sẽ lọc gói tin trên Wireshark bằng bộ lọc chuỗi HTTP: http contains "schtask" và kết quả chỉ cho ra 1 gói tin duy nhất.

<img width="1917" height="251" alt="image" src="https://github.com/user-attachments/assets/96f85406-7d70-4b8d-b650-1b169b89eb2c" />

- Sau đó mình tiếp tục quan sát nội dung mã nguồn script trong luồng HTTP và thấy được hàm CleanerEtc hiển thị rõ câu lệnh đăng ký tác vụ độc hại: `C:\Windows\System32\schtasks.exe /create /tn "Optimize Start Menu Cache Files-S-3-5-21-2236678155-433529325-1142214968-1237" /sc HOURLY /f /mo 3 /tr "C:\Windows\System32\cmd.exe /c powershell -ExecutionPolicy Bypass C:\Users\del.ps1" | Out-Null`

### Q11: Based on your analysis of the second malicious file, What is the MITRE ID of the main tactic the second file tries to accomplish?
- Phân tích hành vi của tập lệnh thứ hai (del.ps1), mục tiêu chính của nó là thực thi các câu lệnh nhằm vô hiệu hóa các tính năng bảo mật, tắt các dịch vụ giám sát hoặc vô hiệu hóa cấu hình diệt virus nhằm giúp mã độc hoạt động mà không bị ngăn chặn.
- Sau đó mình có lên trang MITRE ATT&CK để tìm hiểu thì thì biết nó được xếp vào chiến thuật Defense Evasion (Trốn tránh phòng thủ) mang mã là ` TA0005.`

### Q12: What's the invoked PowerShell script used by the attacker for dumping credentials?

- Để tìm ra tập lệnh PowerShell được kẻ tấn công sử dụng cho mục đích trích xuất thông tin xác thực, mình tiến hành tìm kiếm các gói tin liên quan đến từ khóa này trên Wireshark bằng bộ lọc http contains "dump".
- Kết quả lọc gói tin cho thấy có nhiều luồng giao tiếp HTTP phản hồi thành công (HTTP/1.0 200 OK) và cột "Full request URI" mình quan sát thấy đường dẫn tải xuống trỏ trực tiếp đến tệp tin mang tên Invoke-PowerDump.ps1.

<img width="1917" height="410" alt="image" src="https://github.com/user-attachments/assets/2f02bc98-82bc-4a88-8374-59e1147745df" />

- Phân tích tĩnh (Static Analysis) nội dung mã nguồn thô của tệp lệnh này xác nhận 3 hành vi chính:

  - Mục đích: Trích xuất mã băm mật khẩu (NTLM hashes) từ hệ thống cục bộ.

  - Leo thang đặc quyền: Sao chép token bảo mật của tiến trình lsass để tự động thăng cấp từ quyền Administrator lên SYSTEM.

  - Trích xuất dữ liệu SAM: Truy cập registry HKLM:\SAM và sử dụng BootKey để giải mã, lấy toàn bộ hàm băm mật khẩu của người dùng.

<img width="1917" height="1003" alt="image" src="https://github.com/user-attachments/assets/58660ee6-815f-4346-94ed-abda7ec92c6a" />


### Q13: Understanding which credentials have been compromised is essential for assessing the extent of the data breach. What's the name of the saved text file containing the dumped credentials?

- Phân tích các luồng giao tiếp HTTP tiếp theo trên Wireshark, mình phát hiện máy nạn nhân đã tải xuống và thực thi một tập lệnh điều khiển mang tên ichigo-lite.ps1 .
- Sau đó mình vào sâu bên trong ` ichigo-lite.ps1  ` thì thấy được kẻ tấn công đã sử dụng kỹ thuật làm rối mã nguồn bằng cách mã hóa các câu lệnh quan trọng sang định dạng Base64.

<img width="1917" height="907" alt="image" src="https://github.com/user-attachments/assets/e6ece748-2e80-4643-bc25-713484fbaa54" />

- Sau đó mình dùng CyberChef giải mã thì thu được `Invoke-PowerDump | Out-File -FilePath "C:\ProgramData\hashes.txt"`

Kết quả ` hashes.txt`

### Q14: Knowing the hosts targeted during the attacker's reconnaissance phase, the security team can prioritize their remediation efforts on these specific hosts. What's the name of the text file containing the discovered hosts?

- Cũng trong kết quả câu 13 thì mình phát hiện được danh sách các máy chủ mục tiêu thông qua một tệp tin được tải trực tiếp từ máy chủ C2.

<img width="1265" height="38" alt="image" src="https://github.com/user-attachments/assets/2ea067bb-ec35-4789-a518-91494e387db8" />

Đáp án: `extracted_hosts.txt`

### Q15: After hash dumping, the attacker attempted to deploy ransomware on the compromised host, spreading it to the rest of the network through previous lateral movement activities using SMB. You’re provided with the ransomware sample for further analysis. By performing behavioral analysis, what’s the name of the ransom note file?
- Cũng từ tập lệnh ichigo-lite.ps1 mình phát hiện đoạn mã cuối cùng thực hiện tải xuống tệp thực thi mã độc từ máy chủ C2 `$downloadDestination = "C:\ProgramData\javaw.exe"`
- Sau đó mình trích xuất file `javaw.exe` ra ngoài, tính hash và đưa lên VirusTotal để phân tích. Tại Behavioral Analysis mình thấy được các đường dẫn tệp được hệ thống ghi nhận, cụ thể là `C:\Users\<USER>\# DECRYPT FILES BLUESKY #.txt`. Mẫu mã độc này khi thực thi hành vi mã hóa tập tin trên hệ thống sẽ đồng thời tạo ra các tệp thông báo tống tiềnvới tên định dạng cố định này tại các thư mục người dùng.

<img width="942" height="481" alt="image" src="https://github.com/user-attachments/assets/5f4bbc86-c490-4a33-8675-49659f579863" />

Đáp án ` # DECRYPT FILES BLUESKY #`

### Q16: n some cases, decryption tools are available for specific ransomware families. Identifying the family name can lead to a potential decryption solution. What's the name of this ransomware family?

- Cũng từ kết quả Virustotal ở câu 15 thì mình thấy được nhãn nhận diện từ các hãng bảo mật đã chỉ định họ mã độc tống tiền này thuộc về dòng `bluesky`

<img width="1835" height="730" alt="image" src="https://github.com/user-attachments/assets/03fd3886-b4aa-47d8-9bb5-3e5da062e40d" />
