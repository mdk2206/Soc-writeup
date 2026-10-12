# AzurePot Lab

## 1. Bối cảnh

Bài Lab mô phỏng một sự cố trên máy chủ Ubuntu Linux được triển khai làm honeypot trên Azure vào đầu tháng 10, nhằm theo dõi các hoạt động khai thác lỗ hổng CVE-2021-41773 (Apache HTTP Server 2.4.49). Ban đầu, hệ thống thu hút rất nhiều cryptominer, vì vậy người quản trị đã đặt một cron script để xóa các file tên "kinsing" trong thư mục /tmp, giúp loại bỏ nhiễu và quan sát được các hoạt động đáng chú ý hơn.

Có ba artifact được thu thập theo thứ tự: ảnh đĩa trước, memory dump sau, cuối cùng là kết quả UAC:

- sdb.vhd.gz: ổ đĩa chính, lấy từ Azure disk snapshot
- ubuntu.20211208.mem.gz: memory dump tạo bằng LiME
- uac.tgz: kết quả thu thập từ UAC (Unix-like Artifacts Collector)

Nhiệm vụ của mình là đóng vai người phân tích điều tra số: dựa trên các artifact trên để xác định cách kẻ tấn công xâm nhập và thực thi mã độc, các cơ chế persistence và che giấu mà chúng sử dụng, đồng thời trích xuất các IOCs (tên file, đường dẫn, địa chỉ IP, tiến trình...) phục vụ việc truy vết.

Các công cụ sử dụng trong bài: FTK Imager, Notepad++, grep, awk.

### Câu 1: There is a script that runs every minute to do cleanup. What is the name of the file?

- Đề bài gợi ý đây là một tác vụ lên lịch chạy mỗi phút, thường được cấu hình bằng cron job. Crontab của từng user trên Ubuntu được lưu tại /var/spool/cron/crontabs/, nên mình mở file ảnh đĩa sdb.vhd bằng FTK Imager và đi theo đường dẫn [root] → var → spool → cron → crontabs.
- Mình chọn file crontab của user root và tìm thấy dòng cuối cùng có lịch `* * * * *` (chạy mỗi phút), gọi tới script ẩn nằm trong thư mục /root: `* * * * * /root/.remove.sh`. Header của file cũng cho biết crontab này được cài đặt vào ngày 11/10/2021 lúc 20:05:59.

- <img width="1916" height="1023" alt="image" src="https://github.com/user-attachments/assets/e1e2291f-3cca-4421-a899-728112b2d0cd" />

- Để xác nhận, mình mở nội dung script `/root/.remove.sh` và thấy script này tìm các tiến trình có tên "kinsing" hoặc "kdevtmp" chạy từ /tmp rồi dừng chúng bằng `kill -9`. Sau đó script đổi chủ sở hữu các file `/tmp/k*` sang root và đặt quyền `444` (chỉ đọc) để vô hiệu hóa chúng.
<img width="1917" height="751" alt="image" src="https://github.com/user-attachments/assets/4f9db3e6-1199-40c9-b3a7-9dc792f11965" />

**Đáp án:** `.remove.sh`

### Câu 2: The script in Q1 terminates processes associated with two Bitcoin miner malware files. What is the name of 1st malware file?
- Mình quay lại nội dung script `/root/.remove.sh` ở câu 1 và xem dòng lệnh dùng để tìm tiến trình cần dừng: `ps -ef | egrep "kinsing|kdevtmp" | grep "/tmp" | awk '{ print $2 }'`. Script lọc các tiến trình có tên "kinsing" hoặc "kdevtmp" chạy từ thư mục /tmp, lấy PID bằng `awk` rồi dừng chúng bằng `kill -9`.
- Hai tên file được liệt kê theo thứ tự là `kinsing` rồi đến `kdevtmp`, nên file malware đầu tiên là `kinsing`.
- Để xác nhận, mình kiểm tra thư mục /tmp và quan sát thấy thư mục này chứa file `kinsing` cùng nhiều file có tên dạng `kinsing_...` , đúng với hai tên mà script `.remove.sh` nhắm tới. Điều này cho thấy hệ thống bị nhiễm miner nhiều lần dù cron dọn dẹp chạy mỗi phút.

<img width="1917" height="765" alt="image" src="https://github.com/user-attachments/assets/e9ec1686-db02-4955-a7ae-867cc464f752" />


**Đáp án:** `kinsing`

### Câu 3: The script changes the permissions for some files. What is their new permission?

- Mình tiếp tục dựa vào dữ liệu từ script `.remove.sh` ở câu 1 và chú ý tới lệnh `chmod` Script có dòng `chmod 444 /tmp/k*`, đổi quyền của tất cả file bắt đầu bằng "k" trong thư mục /tmp.

**Đáp án:** `444`

### Câu 4: 
