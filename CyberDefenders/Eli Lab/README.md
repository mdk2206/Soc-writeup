# Eli Lab
## 1. Bối cảnh 
Bài Lab mô phỏng một sự cố trên máy Chromebook. Người dùng báo cáo trình duyệt hoạt động bất thường và một số file bị mất. Đội SOC nghi ngờ có truy cập trái phép và hành vi đánh cắp dữ liệu, và thu thập một bản ảnh pháp y của thiết bị để điều tra.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra số: phân tích ảnh pháp y để xem xét hoạt động của người dùng, dữ liệu ứng dụng và các dấu vết duyệt web, từ đó dựng lại diễn biến sự cố, xác định hành vi truy cập trái phép và dữ liệu bị ảnh hưởng. Bài sử dụng các tài nguyên về phân tích dữ liệu Chrome và vị trí lưu dữ liệu trên Chromebook, trong đó có công cụ Hindsight.
## 2. Điều tra
### Q1: The folder to store all your data in - How many files are in Eli's downloads directory?
- Mình tìm đến địa chỉ decrypted/mount/user/Downloads/ nơi lưu tất cả những tệp tải xuống của người dùng thì phát hiện có `6` file được tải xuống.

<img width="987" height="253" alt="Screenshot 2026-11-08 195353" src="https://github.com/user-attachments/assets/8e5f5c12-ff45-45c0-9db3-37c7004e6a0e" />


### Q2: Smile for the camera - What is the MD5 hash of the user's profile photo?
