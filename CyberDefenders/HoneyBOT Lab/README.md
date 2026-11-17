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

