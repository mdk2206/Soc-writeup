# RetailBreach Lab
## 1. Bối cảnh 
Bài Lab mô phỏng một sự cố tại ShopSphere, một nền tảng bán lẻ trực tuyến. Trong những ngày gần đây, hệ thống ghi nhận các lần đăng nhập quản trị bất thường vào ban đêm, đồng thời khách hàng phàn nàn về các biến động không giải thích được trên tài khoản của họ. Những dấu hiệu này làm dấy lên lo ngại về một vụ xâm nhập, trong đó kẻ tấn công có thể đã truy cập trái phép vào các tài khoản quản trị.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích lưu lượng mạng đã bắt được bằng Wireshark để xác định bản chất và nguồn gốc của vụ xâm nhập, cách kẻ tấn công thâm nhập hệ thống, các TTPs của chúng, trích xuất payload XSS và session token, cùng các lỗ hổng ứng dụng web bị khai thác. Công cụ sử dụng trong bài: Wireshark, Network Miner, Brim.


## 2. Điều tra

### Q1: Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?

- Mình mở file PCAP bằng Wireshark và dùng Statistics → Conversations → IPv4. Máy chủ web là `73.124.17.52` (có mặt ở cả hai cặp), trao đổi với hai địa chỉ bên ngoài: `111.224.180.128` (14.517 gói, 4 MB, 233 luồng TCP trong ~2.292 giây) và `135.143.142.5` (179 gói, 32 kB).

<img width="1917" height="706" alt="image" src="https://github.com/user-attachments/assets/da9a41f2-48b8-46db-ab0f-e39650adf095" />

- Mình lọc `ip.src == 111.224.180.128 && http.request` và thấy 4.647 request tới host `shopsphere.com`, trong đó có hàng loạt request dồn dập tới các file ẩn và file nhạy cảm như `/.bash_history`, `/.bashrc`, `/.git/HEAD`, `/.htaccess`, `/.htpasswd`, `/.cvs`, `/.listing`. Đây là hành vi dò tìm tự động các file bị lộ trên máy chủ web, khác hẳn lưu lượng bình thường của người dùng. Vì vậy mình xác định **111.224.180.128** là IP của kẻ tấn công.

<img width="1915" height="810" alt="image" src="https://github.com/user-attachments/assets/0aaa16bf-22d3-4c5a-83a6-d6a6f710dacd" />


### Q2: The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?

- Từ kết quả ở câu 1, tại các gói tin thăm dò mà kẻ tấn công gửi đi, trường User-Agent cũng đã hiện rất rõ công cụ đó chính là `gobuster`

### Q3: Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?

