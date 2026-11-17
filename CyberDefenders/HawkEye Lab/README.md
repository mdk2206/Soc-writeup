# HawkEye Lab
## 1. Bối cảnh 
Bài Lab mô phỏng một sự cố đánh cắp dữ liệu bằng keylogger HawkEye. Một kế toán trong tổ chức nhận được email về một hóa đơn kèm đường link tải xuống. Ngay sau khi mở email, đội giám sát ghi nhận lưu lượng mạng đáng ngờ phát sinh từ máy của người này.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích bản bắt gói mạng bằng Wireshark và CyberChef để dựng lại diễn biến sự cố, xác định các IoCs, các nỗ lực rò rỉ dữ liệu và thông tin đăng nhập bị đánh cắp. Công cụ sử dụng trong bài: Wireshark, Brim, Apackets, MaxMind GeoIP, VirusTotal.

## 2. Điều tra

### Q1: How many packets does the capture have?

- Ở câu này mình sẽ dùng chức năng `Capture File Properties` của wireshark để đọc số lượng gói tin. Kết quả mình đọc được là có tổng `4003` gói tin.

<img width="1217" height="913" alt="image" src="https://github.com/user-attachments/assets/059cd4aa-0c4c-41b0-8a87-34265a6567bb" />

### Q2: At what time was the first packet captured (UTC)?

- Cũng tiếp tục từ kết quả của phần `Capture File Properties` ở câu 1, mình nhìn vào ` First packet: 2019-04-11 03:37:07 `, nhưng vì do đây đang hiển thị theo múi giờ của máy tính là `UTC+7` mà đề bài lại yêu cầu theo múi giờ UTC nên đáp án cuối cùng sẽ là `2019-04-10 20:37`

### Q3: What is the duration of the capture?

- Cũng từ kết quả ở phần `Capture File Properties` của câu 1 mình nhìn vào cột `Elapsed` nó có giá trị là `01:03:41`.

### Q4: What is the most active computer at the link level?

- Ở câu này mình sẽ điều hướng tới **Statistics → Endpoints → Ethernet** để tìm ra thiết bị truyền/nhận nhiều dữ liệu nhất. Kết quả cho thấy địa chỉ MAC đứng ở vị trí đầu tiên với tổng số gói tin lớn nhất (4,003 gói thf sin) là `00:08:02:1c:47:ae`.

<img width="756" height="251" alt="image" src="https://github.com/user-attachments/assets/61655761-b52d-4f5b-a81f-330ae58316fb" />

### Q5: Manufacturer of the NIC of the most active system at the link level?

- Ở câu 4 mình đã tìm được địa chỉ MAC là `00:08:02:1c:47:ae`. Sau đó mình tách 3 byte đầu tiên (OUI) là `00:08:02` để tra cứu mã OUI này trên cơ sở dữ liệu nhà sản xuất thiết bị mạng và xác định được tên nhà sản xuất card mạng là **Hewlett Packard**.

### Q6: Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

- Từ kết quả thu được ở Q5, mình tiến hành tra cứu thông tin của NIC này thì biết được trụ sở chín của Hewlett-Packard / HP nằm tại thành phố **Palo Alto, bang California, Hoa Kỳ**

### Q7: The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?

- Ở câu này mình sẽ truy cập menu **Statistics → Endpoints** và chọn tab **IPv4** để xem danh sách các địa chỉ mạng xuất hiện.
- Mình quan sát các địa chỉ IP thuộc phân đoạn `10.4.10.0/24`, và lọc được tổng cộng 4 địa chỉ xuất hiện trong bảng thống kê là : `10.4.10.2`, `10.4.10.4`, `10.4.10.132` và `10.4.10.255`. Trong đó `10.4.10.255` chính là địa chỉ Broadcast nên đáp án câu này sẽ là `3`.

<img width="1361" height="383" alt="image" src="https://github.com/user-attachments/assets/d630564c-4b8a-497b-965e-f3e331542899" />


### Q8: What is the name of the most active computer at the network level?

- Từ kết quả ở câu 7 thì mình xác định được máy có IP `10.4.10.132` chính là máy có số lượng gói tin nhiều nhất ` 4003`.
- Sau đó để tìm chính xác tên của thiết bị này thì mình sẽ dùng bộ lọc `ip.addr==10.4.10.132 && dhcp` lọc các gói tin giao thức DHCP liên quan đến thiết bị này.

<img width="1917" height="272" alt="image" src="https://github.com/user-attachments/assets/ccbce3ac-18e1-4a0a-9db1-119d5c4220b7" />


- Kết quả trả về gói tin Packet 3263 (DHCP Inform) được máy 10.4.10.132 gửi quảng bá tới địa chỉ 255.255.255.255.

- Sau đó mình mở rộng gói tin ở phần Host Name thì xác định được tên định danh của máy trạm là `Beijing-5cd1-PC`.

### Q9: What is the IP of the organization's DNS server?

- Ở câu này mình sẽ dùng bộ lọc `dns` để lọc toàn bộ lưu lượng truy vấn phân giải tên miền của máy nạn nhân.

<img width="1917" height="788" alt="image" src="https://github.com/user-attachments/assets/3defe5de-44c0-47a7-bebe-e86e83d3d934" />

- Mình quan sát danh sách gói tin hiển thị, toàn bộ các yêu cầu phân giải tên miền (Standard query) xuất phát từ máy trạm nạn nhân (10.4.10.132)  đều có địa chỉ đích trỏ tới `10.4.10.4`.

### Q10: What domain is the victim asking about in packet 204?

- Mình sẽ dùng bộ lọc `frame.number == 204` để cô lập gói tin số 204.


<img width="1917" height="222" alt="image" src="https://github.com/user-attachments/assets/44fb7a3c-07bf-4ba4-997f-632aa983af71" />

- Gói tin này được gửi từ máy trạm nạn nhân (`10.4.10.132`) tới máy chủ DNS nội bộ của tổ chức (`10.4.10.4`).

- Quan sát cột `Info`, nội dung hiển thị là `Standard query 0xa002 A proforma-invoices.com` — cho thấy máy nạn nhân đang gửi yêu cầu phân giải bản ghi địa chỉ IPv4 cho tên miền `proforma-invoices.com`.

### Q11: What is the IP of the domain in the previous question?

- Từ kết quả câu Q10, mình biết được máy trạm nạn nhân (10.4.10.132) đã gửi yêu cầu phân giải tên miền proforma-invoices.com  tới máy chủ DNS nội bộ (10.4.10.4) tại Packet 204. Sau đó dựa vào mã giao dịch 0xa002 cùng liên kết tự động [Response In: 206], mình xác định được gói tin phản hồi từ máy chủ `10.4.10.4 `gửi trả về cho 10.4.10.132 nằm tại Packet 206

- Sau đó mình dùng bộ lọc `frame.number == 206` để cô lập gói tin phản hồi

- Tại mục Answers, bản ghi trả lời hiển thị chi tiết: `proforma-invoices.com: type A, class IN, addr 217.182.138.150`. Đồng nghĩa với việc IP của tên miền mà máy nạn nhân đã truy vấn là `217.182.138.150`

<img width="906" height="617" alt="image" src="https://github.com/user-attachments/assets/2f5475e6-c4de-40f2-9cb6-9c8155d9f874" />

### Q12: Indicate the country to which the IP in the previous section belongs.

- Dựa vào IP đã thu thập được ở câu trước, mình tiến hành tra cứu trên IPinfo thì biết được nó xuất phát từ `France`


<img width="1166" height="612" alt="image" src="https://github.com/user-attachments/assets/35487856-dc6b-4de3-b741-d5f2a3761055" />

### Q13: What operating system does the victim's computer run?

- Ở câu này mình sẽ dùng filter `http.user_agent` để lọc các yêu cầu HTTP có đính kèm thông tin trình duyệt và hệ thống, sau đó mở chi tiết gói tin Packet 210.


<img width="1917" height="226" alt="image" src="https://github.com/user-attachments/assets/7888ecd7-01e4-484c-b1e9-a5505e672dc2" />

- Ở phần User-Agent mình xác định được hệ điều hành chính là ` Windows NT 6.1` .


<img width="1917" height="457" alt="image" src="https://github.com/user-attachments/assets/69280aa1-d64f-4834-927d-639d8b048144" />

### Q14: What is the name of the malicious file downloaded by the accountant?

- Mình sẽ truy cập **File → Export Objects → HTTP** để liệt kê toàn bộ các tệp tin được truyền qua giao thức HTTP.


<img width="877" height="402" alt="image" src="https://github.com/user-attachments/assets/f6e97bfd-ec19-49e1-a7d2-2f5687e61b2e" />

- Tại đây mình phát hiện đối tượng tải file về từ `proforma-invoices.com` có định dạng `application/x-msdownload`, dung lượng `2025 kB` và tên tệp là **`tkraw_Protected99.exe`**.

### Q15: What is the md5 hash of the downloaded file?

- Ở câu này mình sẽ trích xuất file ra máy sau đó tính hash. Kết quả thu được là `71826BA081E303866CE2A2534491A2F7`


<img width="1405" height="150" alt="image" src="https://github.com/user-attachments/assets/2fa1daeb-5a74-4ccb-a0a4-950fa9329c64" />


### Q16: What software runs the webserver that hosts the malware?

- Từ kết quả câu Q14, gói yêu cầu tải tệp GET /proforma/tkraw_Protected99.exe ở Packet 210 được máy chủ phản hồi tại Packet 3155. Sau đó mình tiến hành dùng bộ lọc `frame.number == 3155` để định vị chính xác vị trí của gói tin phản hồi.

- Mở rộng gói tin ở trường `Server` mình ghi nhận được máy chủ là ` LiteSpeed`


<img width="955" height="417" alt="image" src="https://github.com/user-attachments/assets/e8e960e5-eff4-4abb-b7a7-e4ff4acd4878" />


### Q17: What is the public IP of the victim's computer?

- Sau khi tệp thực thi độc hại tkraw_Protected99.exe được tải về, mình phát hiện lưu lượng mạng xuất hiện chuỗi các yêu cầu HTTP GET / không kèm tiêu đề User-Agent gửi tới phân miền `bot.whatismyipaddress.com`.


<img width="962" height="415" alt="image" src="https://github.com/user-attachments/assets/c0c1cc03-5f8c-4105-a723-7dfc42606c42" />

- Mình chọn ngẫu nhiên gói `3382` và thấy được gói tin phàn hồi của nó là `3384`. Ở gói tin `3384`, ở phần Line-based text data: text/html (1 lines) ở khung chi tiết gói tin, dòng dữ liệu văn bản trả về chính xác chuỗi địa chỉ IPv4 `173.66.146.112`

### Q18: In which country is the email server to which the stolen information is sent?

- Mình sẽ dùng bộ lọc ` smtp ` để cô lập các phiên truyền tải email phát sinh sau khi tệp mã độc tkraw_Protected99.exe được thực thi.


<img width="1917" height="790" alt="image" src="https://github.com/user-attachments/assets/7012e116-0d54-4c9d-a03e-550fbf319085" />

- Danh sách kết quả ghi nhận chuỗi gói tin trao đổi định kỳ qua giao thức SMTP giữa máy trạm nạn nhân (10.4.10.132) và máy chủ thư điện tử bên ngoài có địa chỉ IP `23.229.162.69`.
-  Sau đó mình tiến hành tra cứu IP này trên IPInfo thì ghi nhận được nó xuất phát từ ` United States`.

  ### Q19: Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?

- Mình sẽ lọc lưu lượng gửi thư điện tử bằng bộ lọc **`smtp`** và truy cập vào gói tin khởi đầu của phiên tuồn dữ liệu đầu tiên tại **Packet 3175**.

- Mình mở rộng gói tin tại phần  `Response parameter:` đầu tiên hiển thị đầy đủ dịch vụ của máy chủ:
 `p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:38:15 -0700`

### Q20: To which email account is the stolen information sent?

- Mình tiếp tục sử dụng gói tin khởi đầu phiên gửi dữ liệu đánh cắp đầu tiên ở câu 19. Sau đó xem luồng stream của gói này. Tại quá trình xác thực tài khoản (`AUTH login`) mã độc gửi chuỗi tên đăng nhập mã hóa Base64 `c2FsZXMuZGVsQG1hY3dpbmxvZ2lzdGljcy5pbg==`.

<img width="1071" height="605" alt="image" src="https://github.com/user-attachments/assets/5d399862-03fa-4039-ba3a-f042e883e4e7" />

- Sau khi giải mã bằng CyberChef thì mình thu được địa chỉ email đã gửi dữ liệu đánh cắp là ` sales.del@macwinlogistics.in `

### Q21: What is the password used by the malware to send the email?

- Cũng từ kết quả của luồng stream ở câu trước sau khi gửi user để đăng nhập thì máy chủ có thêm một phản hồi `334 UGFzc3dvcmQ6` giải mã ra đó chính là yêu cầu `password`. Tiếp đó mã độc gửi chuỗi mật khẩu đã mã hóa Base64 là `U2FsZXNAMjM=` giải mã ra chính là `Sales@23` và được máy chủ chấp thuận bằng thông báo 235 Authentication succeeded.

<img width="1430" height="885" alt="image" src="https://github.com/user-attachments/assets/594bd210-cea0-4143-b782-19832487dd0b" />


### Q22: Which malware variant exfiltrated the data?

- Cũng ở luồng stream đang điều tra, mình phát hiện trường `Subject: =?utf-8?B?SGF3a0V5ZSBLZXlsb2dnZXIgLSBSZWJvcm4gdjkgLSBQYXNzd29yZHMgTG9ncyAtIHJvbWFuLm1jZ3VpcmUgXCBCRUlKSU5HLTVDRDEtUEMgLSAxNzMuNjYuMTQ2LjExMg==?=` . Sau khi giải mã thì nó chính là `HawkEye Keylogger - Reborn v9 - Passwords Logs - roman.mcguire \ BEIJING-5CD1-PC - 173.66.146.112` .

### Q23: What are the bankofamerica access credentials? (username:password)

- Tiếp tục trong luồng stream ở phần thân mình tiếp tục nhìn thấy một đoạn mã base64  rất dài và đây có lẽ là danh sách chứa dữ liệu được đánh cắp.

<img width="916" height="747" alt="image" src="https://github.com/user-attachments/assets/d8c35d83-b410-4f54-8b1d-4e5bcbd736d6" />

- Sau khi giải mã bằng CyberChef thì mình thu được những thông tin đánh cắp được gửi theo từng đoạn:

<img width="1265" height="542" alt="image" src="https://github.com/user-attachments/assets/0ab275ea-839e-4dbb-8545-0aea070ed15b" />

- Về thông tin đăng nhập của bankofamerica đó chính là: `roman.mcguire:P@ssw0rd$`.

### Q24: Every how many minutes does the collected data get exfiltrated?

- Mình tiếp tục lọc lưu lượng gửi thư điện tử bằng bộ lọc `smtp` để quan sát các gói tin chào mừng khởi đầu mỗi phiên tuồn dữ liệu từ máy chủ `23.229.162.69`.

- Mình nhìn vào giá trị tại cột **Time** (tính bằng giây kể từ khi bắt đầu bắt gói tin) của các phiên SMTP liên tiếp ví dụ như:

-   Phiên 1 (Packet 3175, cổng `49206`):** `69.160215` giây
-  Phiên 2 (Packet 3306, cổng `49211`):** `673.516672` giây
-  Phiên 3 (Packet 3393, cổng `49214`):** `1277.6256` giây

 <img width="1917" height="695" alt="image" src="https://github.com/user-attachments/assets/299d761f-851b-41e0-90d5-b69203218409" />

- Từ những số liệu trên mình tính được độ lệch thời gian là khoảng `10` phút giữa các lần 
