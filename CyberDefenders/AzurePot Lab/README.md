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

### Câu 4: What is the SHA256 of the botnet agent file?

- Từ script `.remove.sh` ở câu 1, mình biết `kinsing` và `kdevtmp...` là các file miner đã bị xử lý. Botnet agent là một thành phần khác nên không nằm trong danh sách này.
- Mình tìm kiếm theo đường dẫn var/tmp thì thấy 1 file khá lạ có tên dk86
- Sau đó mình dùng powershell để tính hash và gửi lên virustotal để phân tích thì kết quả cho ra đúng đây chính là một file mã độc

<img width="1227" height="157" alt="image" src="https://github.com/user-attachments/assets/dad800f1-13cd-49d9-8f9f-89d547501ae3" />

<img width="1906" height="911" alt="image" src="https://github.com/user-attachments/assets/7572b250-ae05-47f1-b02f-425eaae154f7" />

** Đáp án: ** ` 0E574FD30E806FE4298B3CBCCB8D1089454F42F52892F87554325CB352646049 `

### Câu 5: What is the name of the botnet in Q4?

- Mình cũng tiếp tục sử dụng dữ liệu trên Virustoral và thấy file được nhiều engine gán nhãn thuộc họ ` Tsunami `

<img width="1877" height="565" alt="image" src="https://github.com/user-attachments/assets/8bd7ab48-0dca-4c27-98db-28509c80c1cf" />


### Câu 6: What IP address matches the creation timestamp of the botnet agent file in Q4?

- Trong FTK Imager, thời gian tạo file `dk86` trong /var/tmp là 2021-11-11 19:09:51.
- Sau đó mình mở nhật kí Web ở đường dẫn  /var/log/apache2 vào thời điểm 2021-11-11 19:09:51 và phát hiện 1 địa chỉ IP `141.135.85.36`

<img width="1832" height="31" alt="image" src="https://github.com/user-attachments/assets/c90e656e-a09d-4c2e-a803-859c1b366fbd" />

** Đáp án: ** ` 141.135.85.36 `

### Câu 7: What URL did the attacker use to download the botnet agent?

- Cũng tiếp tục trong nhật kí của Apache và phát hiện kẻ tấn công dùng nhiều lệnh `wget ` để tải file. Mình tìm đến lệnh wget đầu tiên và phát hiện được URL là ` http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86`

<img width="1847" height="51" alt="image" src="https://github.com/user-attachments/assets/02de5434-4ae2-423d-befd-677078ad4c4f" />

**Đáp án:** `http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86`

### Câu 8: What is the name of the file that the attacker downloaded to execute the malicious script and subsequently remove itself?

- Ở câu này mình sẽ tiếp tục phân tích nhật ký lỗi của Apache (`error.log`), phạm vi sẽ là trong tháng 11 và tìm các lệnh `wget`/`curl`
- Sau đó mình phát hiện thấy một loạt log chưa các chuỗi base64 rất bất thường

<img width="1905" height="816" alt="image" src="https://github.com/user-attachments/assets/413bc17f-76cd-4cf2-9270-9e17e04b2787" />

- URL này có IP là 116.203.212.184 và được truy cập nhiều lần thông qua lệnh curl
- Sau đó mình tiến hành giải mã các chuỗi base64 này trên CyberChef thì phát hiện ra một file hết sức đáng ngờ ` .install`

<img width="965" height="527" alt="image" src="https://github.com/user-attachments/assets/cc608303-0dd9-4169-a996-710eead871c7" />

- Mình tiếp tục giải mã chuỗi base64 từ output thứ nhất và phát hiện một Script bao gồm ` rm -rf .install ` có tác dụng xóa đệ quy một tệp  có tên .install khỏi hệ thống trùng hợp với yêu cầu của đề bài

<img width="972" height="487" alt="image" src="https://github.com/user-attachments/assets/80cbeef2-e005-4af3-a148-239bd14c478b" />

** Đáp án: ** `.install`

### Câu 9: The attacker downloaded SH scripts. What are the names of these files?

- Từ yêu cầu của đề bài thì mình tiếp tục tìm trong nhật kí lỗi apache bằng từ khóa ` .sh ` và phát hiện một số file sh được tải từ các lệnh `wget ` và `curl` để lấy các script shell từ các máy chủ từ xa

<img width="1336" height="633" alt="image" src="https://github.com/user-attachments/assets/1095d993-6208-4100-a0eb-2eaa285d1342" />

** Đáp án: ** `0_cron.sh,0_linux.sh, ap.sh`
