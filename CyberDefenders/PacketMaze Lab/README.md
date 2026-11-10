# PacketMaze Lab
## 1. Bối cảnh
Bài Lab mô phỏng một sự cố trên máy chủ nội bộ của một công ty. Hệ thống giám sát gắn cờ lưu lượng mạng bất thường từ máy chủ này, gồm nhiều kết nối đi ra một địa chỉ IP bên ngoài chưa rõ nguồn gốc, gợi ý khả năng dữ liệu đã bị đánh cắp.

Nhiệm vụ của mình là đóng vai chuyên viên phân tích: điều tra các bản ghi lưu lượng mạng được cung cấp để xác định nguồn của hoạt động đáng ngờ, phương thức mà kẻ tấn công đã dùng để xâm nhập và đưa dữ liệu ra ngoài, từ đó trích xuất các IOCs phục vụ việc ngăn chặn và khắc phục.
## 2. Điều tra
### Q1: What is the FTP password?
- Ở câu này, mình áp dụng bộ lọc hiển thị ftp để cô lập các phiên giao tiếp thuộc giao thức này.
<img width="1917" height="605" alt="image" src="https://github.com/user-attachments/assets/9a60f077-3a2b-406e-b6b3-f33d8c62044f" />
- Quan sát cột Info của các gói tin, mình thấy quá trình đăng nhập diễn ra rất rõ ràng. Máy khách gửi tên đăng nhập thông qua gói tin Request: `USER kali`. Ngay sau đó, máy khách tiếp tục gửi gói tin chứa mật khẩu là Request: `PASS AfricaCTF2021`. Gói tin tiếp theo báo Response: `230 Login successful`.

### Q2: What is the IPv6 address of the DNS server used by 192.168.1.26

- Mình sử dụng bộ lọc `dns && ip.src == 192.168.1.26` để truy vấn tên miền xuất phát từ máy mục tiêu và mình xác định được IP của máy chủ DNS nội bộ là ` 192.168.1.10`

<img width="1917" height="350" alt="image" src="https://github.com/user-attachments/assets/a633e0b5-a9a7-45ba-8ec9-5edcf062850a" />

- Sau đó mình vào 1 gói tin bất kì thì thấy được Destination MAC là `ca:0b:ad:ad:20:ba` tức đây chính là MAC của DNS. Dựa vào địa chỉ MAC này mình dùng nó để tìm ra IPv6 bằng cách dùng bộ lọc ` ipv6 && eth.src == ca:0b:ad:ad:20:ba`

<img width="1916" height="538" alt="image" src="https://github.com/user-attachments/assets/3d4bfa00-e6a0-49fa-b4e6-abb615faa996" />

- Kết quả mình thấy được IPv6 của máy chủ DNS là `fe80::c80b:adff:feaa:1db7`

### Q3: What domain is the user looking up in packet 15174?

- Để tìm chính xác gói tin theo yêu cầu, mình áp dụng bộ lọc `frame.number == 15174`. Kết quả trả về duy nhất một gói tin thuộc giao thức DNS. Quan sát trực tiếp tại cột Info, gói tin thể hiện rõ đây là một truy vấn tiêu chuẩn (Standard query) nhằm phân giải địa chỉ IP cho tên miền `www.7-zip.org`.

<img width="1917" height="262" alt="image" src="https://github.com/user-attachments/assets/5b3d2d79-2729-4e92-885e-9b6b962afa5e" />

### Q4: How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?

- Để xác định chính xác số lượng gói tin gửi một chiều từ máy nguồn đến máy đích thông qua giao thức UDP, mình áp dụng bộ lọc kết hợp 3 điều kiện trên Wireshark: `ip.src==192.168.1.26 && ip.dst == 24.39.217.246 && udp ` và mình thấy có tổng ` 10 ` gói tin tất cả.

<img width="1917" height="460" alt="image" src="https://github.com/user-attachments/assets/1005ebe5-293a-4170-902d-21e08fbbb57d" />


### Q5: What is the MAC address of the system under investigation in the PCAP file?

- Đầu tiên mình sẽ tiến hành kiểm tra các phiên kết nối ` Statistics -> Conversations -> UDP ` mình thấy được một địa chỉ IP nội bộ `192.168.1.26` đang liên tục khởi tạo hàng loạt luồng truyền tải gói tin hướng ra các địa chỉ IP công cộng bên ngoài một cách bất thường. Điều này chỉ ra đây là máy trạm tâm điểm cần điều tra

<img width="1916" height="766" alt="image" src="https://github.com/user-attachments/assets/36246af1-b488-4b67-bef8-a59e52e30a3b" />

- Sau đó mình tiếp tục tìm địa chỉ MAC bằng bộ lọc ` ip.src == 192.168.1.26 ` và thu được ` c8:09:a8:57:47:93 `

<img width="1101" height="267" alt="image" src="https://github.com/user-attachments/assets/0bc4e904-0f80-4cdf-9075-8455e1986e3a" />


### Q6: What was the camera model name used to take picture 20210429_152157.jpg?

- Đầu tiên mình sẽ tiến hành trích xuất tập tin hình ảnh được truyền tải qua giao thức FTP bằng cách `File -> Export Objects -> FTP-DATA.`.
- Sau khi trích xuất xong thì mình sẽ dùng `exiftool` để đọc toàn bộ siêu dữ liệu bên trong và thu được `Camera Model Name` là `LM-Q725K`

<img width="900" height="628" alt="image" src="https://github.com/user-attachments/assets/eae5f7f8-ba11-4f0c-94a9-caeb39b8c224" />

### Q7: What is the ephemeral public key provided by the server during the TLS handshake in the session with the session ID: da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff?

- Mình sẽ tiến hành định vị chính xác gói tin thuộc phiên giao dịch mã hóa mục tiêu bằng bộ lọc ` tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`

<img width="1917" height="282" alt="image" src="https://github.com/user-attachments/assets/7fe72825-25c0-4740-bdd0-12123a8f4c1d" />

- Sau đó mình mở rộng chi tiết gói tin tại mục Transport Layer Security (TLS) -> TLSv1.x Record Layer: Handshake Protocol: Server Key Exchange và thu được public key là `04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d`

### Q8: What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?

- Mình sẽ tiến hành định vị gói tin bắt tay bảo mật hướng đến tên miền ProtonMail bằng bộ lọc `tls.record.content_type == 22 && tls.handshake.extensions_server_name == "protonmail.com"` (mã 22 đại diện cho trường Content Type mang kiểu Handshake).

<img width="1917" height="360" alt="image" src="https://github.com/user-attachments/assets/87e85fd6-7792-418f-a0ee-340217fe5f31" />

- Mình mở rộng chi tiết gói tin tại mục Transport Layer Security (TLS) -> TLSv1.3 Record Layer: Handshake Protocol: Client Hello tìm đến trường Random thì thu được Client Random là `24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70`

<img width="1287" height="265" alt="image" src="https://github.com/user-attachments/assets/ddfc45f5-ea31-4799-a1a1-5802e3763a08" />

### Q9: Which country is the manufacturer of the FTP server’s MAC address registered in?

- Mình sẽ tiến hành dùng bộ lọc `ftp` để cô lập các gói tin ftp.
- Sau đó mình quan sát gói tin đầu tiên, tại cột Info hiển thị thông điệp phản hồi Response: 220 Welcome to Hacker FTP service.. Đây là lời chào được gửi đi từ phía máy chủ FTP đến máy trạm.

<img width="1917" height="741" alt="image" src="https://github.com/user-attachments/assets/235325d7-05ce-42a4-8559-71e1ae43c1ca" />

- Mình mở rộng mục `Ethernet II` để xem MAC thì thu giá trị là ` 08:00:27:a6:1f:86`
- Cuối cùng mình tra cứu MAC này thì biết được dải địa chỉ này thuộc về tổ chức được đăng ký tại Hoa Kỳ.

### Q10: What time was a non-standard folder created on the FTP server on the 20th of April?

- Mình sẽ sử dụng bộ lọc `ftp` để theo dõi các lệnh điều khiển, xác định phiên đăng nhập thành công của người dùng (USER kali, PASS ...).

<img width="1917" height="868" alt="image" src="https://github.com/user-attachments/assets/33cba99d-1220-4aa9-b210-3f893b2c9b5f" />

- Tại đây mình quan sát các lệnh LIST được thực thi để kiểm tra cấu trúc thư mục trên máy chủ FTP.
- Sau đó mình tiếp tục điều tra sâu vào gói LIST này thì thấy nó kích hoạt kết nối dữ liệu thụ động (PASV) để máy chủ trả về danh sách tệp và thư mục.

<img width="805" height="855" alt="image" src="https://github.com/user-attachments/assets/73bf9da9-c694-479e-ab9d-f3bc52e1a5ac" />

- Cuối cùng mình điều tra gói tin phản hồi dữ liệu tương ứng ở luồng TCP tiếp theo thì kết quả cho ra danh sách các thư mục hệ thống mặc định (như Desktop, Documents, Downloads, Music, Pictures,...) và kèm theo một mục lạ mang tên `ftp` với thời gian là `20 tháng 4` khớp với câu hỏi đề ra có giờ tạo là `17:53`

<img width="930" height="327" alt="image" src="https://github.com/user-attachments/assets/e91a16b8-ea0b-4e6d-83d3-8204f347b24c" />

### Q11: What URL was visited by the user and connected to the IP address 104.21.89.171?

- Mình sẽ dùng bộ lọc `ip.dst == 104.21.89.171 && http` để cô lập các gói tin gửi đến `104.21.89.171` kèm giao thức HTTP.

<img width="1917" height="305" alt="image" src="https://github.com/user-attachments/assets/01034cce-3cf2-4b23-9c36-b5ccccbb7bc3" />


- Kết quả cho ra đúng 1 gói tin và mình tìm được URL là `http://dfir.science/`

<img width="1480" height="467" alt="image" src="https://github.com/user-attachments/assets/83489bb7-7f97-4180-af46-58211e2ea293" />



