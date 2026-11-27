# MrGamer Lab
## 1. Bối cảnh 

Bài Lab cung cấp một ảnh hệ thống Linux của một người dùng thích chơi game và trò chuyện với bạn bè. Trong các artifact của hệ thống có những hoạt động đáng ngờ được ghi nhận.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích ảnh hệ thống để phát hiện các bất thường, dựng lại hành vi của người dùng và lần theo các dấu vết số, đồng thời trả lời các câu hỏi theo ngữ cảnh dựa trên bằng chứng thu được từ hệ thống bị xâm nhập. Công cụ sử dụng trong bài: CyberChef, DCode, DB Browser for SQLite, Unfurl, Arsenal Image Mounter, Autopsy.

## 2. Điều tra

### Q1: What is the name of the utility or library for which the user was exploring exploits?

- Đầu tiên, sau khi nạp ảnh đĩa `LenovoFinal.E01` vào Autopsy, mình truy cập vào `/home/rafael/.bash_history` để xem lịch sử các câu lệnh mà người dùng `rafael` đã chạy trên terminal.

<img width="1912" height="972" alt="image" src="https://github.com/user-attachments/assets/670ae5cb-500b-4e00-b13b-f4899854c99f" />

- Quan sát chuỗi lệnh bên trong cho thấy `rafael` đã cố tình gỡ bỏ OpenJDK 11 để hạ cấp xuống `openjdk-8-jdk`, clone công cụ tạo máy chủ chuyển hướng LDAP `marshalsec`, tải script `powercat.ps1` và clone kho mã khai thác `https://github.com/xiajun325/apache-log4j-rce-poc.git` (sau đó biên dịch file `Log4jRCE.java`).

- Tiếp theo, mình mở thư mục `/home/rafael/` trên Autopsy thì thấy xuất hiện thư mục `minecraft` nằm ngay cạnh các thư mục mã khai thác vừa clone, cho thấy hệ thống mục tiêu mà người dùng nhắm tới là máy chủ trò chơi Minecraft (chạy trên nền tảng Java).

- Để kiểm chứng chéo qua trình duyệt, mình tìm đến đường dẫn `/home/rafael/snap/firefox/common/.mozilla/firefox/mcrcm1xn.default/` (do Firefox trên bản Ubuntu này được cài dưới dạng gói Snap), export đồng thời hai file `places.sqlite` và `places.sqlite-wal` ra ngoài rồi mở bằng DB Browser for SQLite.

- Kiểm tra bảng `moz_places`, mình thấy rõ lịch sử người dùng liên tục tìm kiếm và đọc tài liệu khai thác như `hack minecraft log4j`, `metasploit log4j` và bài viết Exploit-DB *"Apache Log4j 2 - Remote Code Execution (RCE)"*.

<img width="1917" height="1020" alt="image" src="https://github.com/user-attachments/assets/c2d7222f-3612-42fb-a332-ac14c601e790" />

- Tổng hợp dữ liệu từ cả lịch sử dòng lệnh lẫn trình duyệt và đối chiếu với gợi ý `***4*`, mình loại trừ `minecraft`  và `marshalsec`/`metasploit`  để chốt thư viện bị khai thác lỗ hổng là `log4j`.

### Q2: What is the version ID number of the operating system on the machine?


