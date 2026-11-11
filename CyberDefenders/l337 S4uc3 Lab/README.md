# l337 S4uc3 Lab
## 1. Bối cảnh 
Bài Lab mô phỏng một cuộc tấn công có chủ đích. Nhiệm vụ của mình là đóng vai chuyên viên SOC, kết hợp phân tích lưu lượng mạng và dấu vết trên máy chủ để trả lời các câu hỏi về ai, cái gì, ở đâu, khi nào và bằng cách nào của sự cố, rồi dựng lại diễn biến theo dòng thời gian.

## 2. Điều tra 

### Q1: PCAP: Development.wse.local is a critical asset for the Wayne and Stark Enterprises, where the company stores new top-secret designs on weapons. Jon Smith has access to the website and we believe it may have been compromised, according to the IDS alert we received earlier today. First, determine the Public IP Address of the webserver?

### Q2: PCAP: Alright, now we need you to determine a starting point for the timeline that will be useful in mapping out the incident. Please determine the arrival time of frame 1 in the "GrrCON.pcapng" evidence file.

- Mình định  vị gói tin số 1 bằng bộ lọc ` frame.number == 1`. Sau đó vào chi tiết gói tin để xem trường ` UTC Arrival Time` thi thu được thời gian là `22:51:07 UTC`

<img width="1322" height="577" alt="image" src="https://github.com/user-attachments/assets/89ba8497-d47b-44b6-80f7-49ceaedbef17" />

### Q3: PCAP: What version number of PHP is the development.wse.local server running?

- Từ câu 1, máy chủ `development.wse.local` có địa chỉ IP `172.16.0.108`. Mình lọc `ip.src == 172.16.0.108 && http.response && http contains "PHP/"` trong Wireshark để xem các phản hồi HTTP của máy chủ này.

<img width="1917" height="647" alt="image" src="https://github.com/user-attachments/assets/9685fa70-3460-4ff0-bf0e-81a26f45880b" />

- Sau đó mình xem Follow HTTP Stream cho một phản hồi, header có `Server: Apache/2.2.14 (Ubuntu)` và `X-Powered-By: PHP/5.3.2-1ubuntu4.20`, cho thấy máy chủ chạy PHP phiên bản **5.3.2**.

<img width="1265" height="497" alt="image" src="https://github.com/user-attachments/assets/567080a7-3818-43d0-a143-044c33803e06" />

### Q4: PCAP: What version number of Apache is the development.wse.local web server using?

- Cũng trong kết quả của câu 3 thì mình tìm được máy chủ web đang sử dụng phiên bản `Apache/2.2.14`

### Q5: IR: What is the common name of the malware reported by the IDS alert provided?

- Mình mở ảnh cảnh báo IDS được cung cấp và đọc trường tên chữ ký: `ET TROJAN Zeus Bot GET to Google checking Internet connectivity` . Từ đây mình xác định được tên phổ biến của mã độc được báo cáo là **Zeus**.

<img width="972" height="788" alt="image" src="https://github.com/user-attachments/assets/22599c11-0f2a-4f35-91de-8d4cbdf5e8cd" />

### Q6: **PCAP: Please identify the Gateway IP address of the LAN because the infrastructure team reported a potential problem with the IDS server that could have corrupted the PCAP
- Vì pcap có thể bị hỏng nên mình xác định gateway qua địa chỉ MAC. Mình lọc lưu lượng từ `172.16.0.109` tới IP ngoài LAN `74.125.225.112` và xem được MAC đích ở lớp Ethernet II là `00:90:7f:80:9e:b9` (WatchGuard).

- Sau đó từ địa chỉ MAC mình tiếp tục lọc `eth.src == 00:90:7f:80:9e:b9`, mình thấy MAC này xuất hiện với rất nhiều địa chỉ IP nguồn khác nhau, gồm các IP công cộng (`74.125.225.112`, `204.95.26.216`, `204.79.197.200`, `198.116.65.32`), một địa chỉ mạng riêng khác `10.20.0.150`, và `172.16.0.1`. Điều này làm mình suy đoán đây rất có thể là MAC của geteway.

 
<img width="1917" height="557" alt="image" src="https://github.com/user-attachments/assets/cb711827-2627-4b55-910c-50188f4f5b4f" />

<img width="1917" height="562" alt="image" src="https://github.com/user-attachments/assets/01b51138-849f-4735-bb53-79b043fedfae" />

- Để tìm IP của chính gateway, mình loại dần các địa chỉ không thể là nó. Các IP công cộng chỉ là máy chủ ngoài Internet, không thuộc LAN. Địa chỉ `10.20.0.150` nằm ở một mạng riêng khác chứ không phải dải LAN `172.16.0.0/16` đang xét. Chỉ còn `172.16.0.1` vừa nằm trong dải LAN vừa gửi gói bằng đúng MAC này , nên đây chính là địa chỉ IP của gateway trong LAN.

### Q7: IR: According to the IDS alert, the Zeus bot attempted to ping an external website to verify connectivity. What was the IP address of the website pinged?

- Ở câu này mình dùng lại kết quả của bức ảnh cảnh báo IDS đề đã cho, bức ảnh chỉ ra rằng cảnh báo được kích hoạt giữa máy nội bộ `172.16.0.109` và địa chỉ ngoài `74.125.225.112` qua cổng 80.

### Q8: PCAP: It’s critical to the infrastructure team to identify the Zeus Bot CNC server IP address so they can block communication in the firewall as soon as possible. Please provide the IP address?

- Ở câu này mình sẽ phân tích file PCAP bằng engine Suricata tích hợp trong Zui, thực hiện truy vấn lọc các sự kiện mang nhãn cảnh báo (event_type: "alert"). Sau đó tìm từ khóa `Zbot` để tập trung vào dòng mã độc đang được điều tra

- Kết quả cho thấy một loạt sự kiện có chữ kí tấn công `ET MALWARE Zbot POST Request to C2` và có `IP Des` là ` 88.198.6.20 `

<img width="1611" height="891" alt="image" src="https://github.com/user-attachments/assets/9541958c-9a0c-415b-801f-22430f311418" />


<img width="585" height="771" alt="image" src="https://github.com/user-attachments/assets/2f3e8212-e2dd-478e-b765-17d0737c1d17" />


### Q9: PCAP: The infrastructure team also requests that you identify the filename of the “.bin” configuration file that the Zeus bot downloaded right after the infection. Please provide the file name?

- Vì ở câu 8 chúng ta đã xác định được IP của máy chủ C2 là 88.198.6.20 nên mình sẽ dùng bộ lọc ` ip.addr == 88.198.6.20 && http` để lọc các phiên giao tiếp giữa máy nạn nhân và máy chủ C2.

<img width="1917" height="588" alt="image" src="https://github.com/user-attachments/assets/cfd249ec-2138-40e4-9c6b-900f8d8315d6" />

- Ngay lập tức mình phát hiện được 1 gói tin yêu cầu tải tệp `GET /bt.exe HTTP/1.1 ` , trước đó hacker cũng đã ngụy trang file exe như một bức ảnh bằng cách thêm đuôi jpg ` GET /NewDesign.jpg.exe HTTP/1.1`

### Q10: PCAP: No other users accessed the development.wse.local WordPress site during the timeline of the incident and the reports indicate that an account successfully logged in from the external interface. Please provide the password they used to log in to the WordPress page around 6:59 PM EST?

- Theo những câu trước thì mình đã biết máy chủ trang WordPress có IP là `172.16.0.108` từ đó mình dùng bộ lọc `ip.dst == 172.16.0.108 && http` để định vị được những gói tin gửi đến máy chủ đó và phương thức http.

<img width="1912" height="976" alt="image" src="https://github.com/user-attachments/assets/24ecc985-8947-4fa8-ae21-7cccc8396fe4" />

- Tại gói tin số 4282, hệ thống ghi nhận một lệnh `POST /wp-login.php HTTP/1.1` được gửi thẳng tới máy chủ web. Đây chính là thời điểm Form đăng nhập được kẻ tấn công submit.

- Do trang này sử dụng HTTP nên toàn bộ dữ liệu được truyền đi dưới dạng plaintext, vì thế mà mình tìm được pwd là `wM812ugu`

<img width="715" height="447" alt="image" src="https://github.com/user-attachments/assets/ae431fec-cd1f-4151-8eb9-d4a3e7d3cab8" />

### Q11: PCAP: After reporting that the WordPress page was indeed accessed from an external connection, your boss comes to you in a rage over the potential loss of confidential top-secret documents. He calms down enough to admit that the design's page has a separate access code outside to ensure the security of their information. Before storming off he provided the password to the designs page “1qBeJ2Az” and told you to find a timestamp of the access time or you will be fired. Please provide the time of the accessed Designs page?

- Ở câu này mình sẽ dùng công cụ NetworkMiner để tận dụng khả năng phân giải dữ liệu của nó. Ở thẻ Credentials, NetworkMiner cho thấy đã toàn bộ các phiên đăng nhập truyền tải dưới dạng plaintext qua mạng.
` 
<img width="1912" height="845" alt="image" src="https://github.com/user-attachments/assets/f2ba813e-b66e-45f3-8d2a-50c5b650b4e3" />

- Điều mình đặc biệt chú ý đó chính là có tới 2 lần mật khẩu 1qBeJ2Az được sử dụng để xác thực. Tuy nhiên ở lần 1 IP Nguồn là `172.16.0.109`. Đây là IP của máy trạm nằm trong mạng nội bộ nên rất có thể là nhân viên hợp lệ đang làm việc. Còn đối với lần 2 thì IP nguồn chính là ` 172.16.0.1`, đây chính là IP Gateway, nó cho thấy rằng đã có máy ngoài Internet muốn truy cập vào Web Server

- Từ đó mình tìm ra được thời gian truy cập của lần 2 là `23:04:04 UTC`

### Q12: PCAP: What is the source port number in the shellcode exploit? Dest Port was 31708 IDS Signature GPL SHELLCODE x86 inc ebx NOOP

- Dựa trên cảnh báo từ hệ thống IDS cung cấp, cuộc tấn công nhắm vào cổng đích 31708 nên mình sẽ dùng bộ lọc ` udp.dstport == 31708` và `tcp.dstport == 31708` để check, do bộ lọc tcp không trả về kết quả nào nên mình xác định kẻ tấn công đã dùng `udp`.

<img width="1917" height="582" alt="image" src="https://github.com/user-attachments/assets/abcd8b3e-42d5-49d6-939b-f96983d2f917" />

- Ở kết quả trả về cho thấy rất rõ hàng loạt các lệnh truyền tải UDP đi từ IP của Gateway `172.16.0.1 (cổng 39709)` nhắm thẳng đến máy chủ đích `172.16.0.108`.

### Q13: PCAP: What was the Linux kernel version returned from the meterpreter sysinfo command run by the attacker?

- Để tìm kiếm dấu vết của lệnh sysinfo mình đã dùng bộ lọc ` frame contains "sysinfo"`

<img width="1917" height="457" alt="image" src="https://github.com/user-attachments/assets/be4455b4-8b2a-4473-b83f-1c6bde6aeb27" />

- Sau đó tiếp tục mình sẽ xem chi tiết luồng dữ liệu của gói tin để điều tra, mình phát hiện tấn công đã gọi rất nhiều lệnh khác nhau như stdapi_sys_config_getuid, stdapi_net_config_get_interfaces và stdapi_sys_config_sysinfo. Ngay phía dưới khối lệnh `stdapi_sys_config_sysinfo`, dữ liệu trả về từ máy chủ mục tiêu hiển thị rõ ràng chuỗi thông tin:`Linux WWW01 2.6.32-38-server #83-Ubuntu SMP Wed Jan 4 11:26:59 UTC 2012 x86_64`

### Q14: PCAP: What is the value of the token passed in frame 3897?

- Mình sẽ định vị gói tin 3897 bằng filter ` frame.number == 3897`

<img width="1917" height="227" alt="image" src="https://github.com/user-attachments/assets/038ff7d7-8418-4a10-812f-3c04ebf3c3c2" />

- Ở phần HTML Form URL Encoded của gói tin mình tìm được token có giá trị là `b7aad621db97d56771d6316a6d0b71e9`

<img width="822" height="440" alt="image" src="https://github.com/user-attachments/assets/01840146-ac2f-4f91-a990-9d4c036813a5" />

### Q15: PCAP: What was the tool that was used to download a compressed file from the webserver?

- Vì đề bài yêu cầu tìm công cụ được sử dụng để tải tệp nén từ máy chủ nên mình sẽ dùng filter ` http.request && ip.dst == 172.16.0.108`

<img width="1917" height="992" alt="image" src="https://github.com/user-attachments/assets/de04e320-b22d-4dda-bd75-5734787cbfc9" />

- Quan sát kết quả lọc, mình phát hiện danh sách các HTTP Request hiển thị rõ một yêu cầu GET nhắm tới một tệp nén có định dạng `.tar.gz` tại đường dẫn `/unimportant.tar.gz`. Sau đó mình kiểm tra trường `User-Agent` thì nhận được chuỗi định danh`Wget/1.1.4 (linux-gnu)`, tức là kẻ tấn công đã dùng `wget` để tải file.

### Q16: PCAP: What is the download file name the user launched the Zeus bot?

- Vì ở câu 8 mình đã xác định được IP của máy chủ C2 là `88.198.6.20` nên ở câu này mình sẽ dùng filter `http and ip.addr == 88.198.6.20` để lọc các gói tin mà máy nạn nhân đã tải về.
 
  <img width="1917" height="635" alt="image" src="https://github.com/user-attachments/assets/edd9cdaf-8a9d-4733-8305-7099ba824295" />

- Bảng kết quả cho thấy danh sách các yêu cầu HTTP GET gửi đến máy chủ C2 như: Tải tệp ngụy trang `NewDesign.jpg.exe`, tải tệp thực thi `bt.exe`, tải tệp cấu hình `cf.bin`

- Mình tiến hành trích xuất cả 2 tệp `NewDesign.jpg.exe` và `bt.exe` ra ngoài để phân tích trên virustotl, kết quả cho thấy `bt.exe` được xác định là độc hại còn `NewDesign.jpg.exe` thì không. Nên mình suy đoán `NewDesign.jpg.exe` có thể là tệp mồi nên đáp án câu này là `bt.exe`

<img width="1917" height="912" alt="image" src="https://github.com/user-attachments/assets/d9bb5750-839a-43cb-8ebb-420b0bd4fec3" />

### Q17: Memory: What is the full file path of the system shell spawned through the attacker's meterpreter session?

- Ở câu này mình sẽ sử dụng plugin linux_psaux để trích xuất toàn bộ các tiến trình đang hoạt động trong bộ nhớ tại thời điểm ghi nhận: ` /opt/volatility2/venv/bin/python /opt/volatility2/vol.py --plugins=/home/khangg/Downloads/grrcon_profile -f ~/Downloads/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_psaux`

- Quan sát kết quả đầu ra từ bảng tiến trình, mình phát hiện chuỗi tiến trình bất thường xuất phát từ tài khoản thực thi của dịch vụ web (UID 33 - Apache): `1274   33     33     sh -c /bin/sh` và `1275   33     33     /bin/sh`

<img width="1283" height="817" alt="image" src="https://github.com/user-attachments/assets/1073171a-9e83-4676-8c81-48176260dff5" />

- Kẻ tấn công đã tận dụng lỗ hổng thực thi mã từ xa trên dịch vụ web để gọi lệnh thông qua sh -c, từ đó kích hoạt và sinh ra một tiến trình shell hệ thống độc lập nhằm duy trì quyền điều khiển tương tác `/bin/sh`.

### Q18: 



 
