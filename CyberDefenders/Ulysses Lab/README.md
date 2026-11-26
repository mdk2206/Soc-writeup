# Ulysses Lab

## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố trên máy chủ Linux phục vụ nghiên cứu. Máy chủ bị gắn cờ vì hoạt động đáng ngờ sau nhiều lần xác thực thất bại. Các nhà phân tích phát hiện dấu hiệu của một cuộc tấn công brute-force, các kết nối đi ra trái phép và những cơ chế persistence khả nghi. Một profile Volatility tùy chỉnh (Debian5_26) được cung cấp để phân tích bản memory dump của hệ thống bị xâm nhập.

Nhiệm vụ của mình là đóng vai chuyên viên điều tra: phân tích memory dump và log bằng Volatility và FTK Imager để dựng lại cuộc tấn công, xác định điểm xâm nhập của kẻ tấn công, tìm các tiến trình độc hại và các payload đã được triển khai, từ đó thu thập các IOCs. Công cụ sử dụng trong bài: Volatility 2 (profile Debian5_26), 010 Editor, Autopsy, FTK Imager, VsCode.


## 2. Điều tra

### Q1: The attacker was performing a Brute Force attack. What account triggered the alert?

- Ở câu này mình sẽ sử dụng FTK Imager mở tệp ảnh phân vùng đĩa `victoria-v8.sda1.img`, điều hướng tới thư mục `/var/log/` và trích xuất tệp nhật ký xác thực `auth.log`.

<img width="1917" height="1017" alt="image" src="https://github.com/user-attachments/assets/f30fdf99-1e7c-49a7-81c0-51e207a0cc42" />

- Sau đó mình lọc các sự kiện xác thực thất bại bằng PowerShell (`Select-String -Path .\auth.log -Pattern "Failed password|authentication failure|Invalid user"`), kết quả phát hiện từ thời điểm `Feb 6 15:16:20` xuất hiện chuỗi tấn công dò mật khẩu (brute-force) qua SSH từ IP `192.168.56.1` nhắm liên tục vào tài khoản `ulysses` (`Invalid user ulysses from 192.168.56.1`).

<img width="1917" height="906" alt="image" src="https://github.com/user-attachments/assets/b94aec5a-e772-4df7-a4f3-c0b3c12635e4" />

### Q2: During investigating the logs. How many failed login attempts were alerted by the same user?

- Từ tệp nhật ký xác thực `auth.log` đã trích xuất tại đường dẫn `/var/log/auth.log`, mình sử dụng PowerShell lọc và đếm trực tiếp tổng số bản ghi xác thực thất bại liên quan tới tài khoản `ulysses` bằng lệnh `(Get-Content .\auth.log | Select-String -Pattern "Failed.*ulysses").Count`.

<img width="1601" height="108" alt="image" src="https://github.com/user-attachments/assets/d4e1e3d6-e859-4415-ba77-d40d04c18972" />

- Kết quả cho ra có tổng cộng `32` lần đăng nhập thất bại được ghi nhận.


### Q3: What kind of system runs on the targeted server?

