# JetBrains Lab
## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố an ninh nghiêm trọng xảy ra trên hệ thống máy chủ web của tổ chức. Kẻ tấn công đã khai thác thành công một lỗ hổng bảo mật trên web server, qua đó tải lên các webshell và chiếm toàn quyền kiểm soát hệ thống. Sau khi có được quyền truy cập, chúng tiếp tục lợi dụng máy chủ bị thỏa hiệp này làm bàn đạp để thực hiện các hoạt động độc hại sâu hơn, bao gồm cả việc thao túng dữ liệu.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra: phân tích tệp PCAP ghi lại lưu lượng trong thời gian diễn ra vụ tấn công để tái dựng dòng thời gian (timeline), xác định điểm xâm nhập ban đầu, nhận diện các công cụ cũng như kỹ thuật mà kẻ tấn công đã sử dụng, từ đó đánh giá mức độ thiệt hại của sự cố.


## 2. Điều tra 

### Q1: Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?

- Mình mở tệp `Capture.pcap` và áp dụng bộ lọc `http.request.method == POST` để kiểm tra các yêu cầu gửi dữ liệu lên máy chủ web.

<img width="1906" height="515" alt="image" src="https://github.com/user-attachments/assets/0a8399ac-74b7-4f50-a832-c255e858f2c9" />

- Kéo xuống danh sách các gói tin đã lọc, tại gói tin số `24825`, mình phát hiện một yêu cầu tải tệp nén `application/zip` bất thường gửi tới đường dẫn quản trị `POST /admin/pluginUpload.html` trên máy chủ đích (`172.31.25.119`) và mình xác định được IP của kẻ tấn công là `23.158.56.196`


### Q2: To identify potential vulnerability exploitation, what version of our web server service is running?

- Để xác định phiên bản dịch vụ web đang chạy, mình áp dụng bộ lọc `http && ip.addr == 23.158.56.196` nhằm theo dõi toàn bộ lưu lượng HTTP qua lại với IP của kẻ tấn công.

<img width="1917" height="485" alt="image" src="https://github.com/user-attachments/assets/dca1890f-c38d-474e-bee6-f268a5ee4907" />

- Quan sát danh sách các gói tin được lọc ra, mình tìm thấy yêu cầu thăm dò thông tin máy chủ `GET /hax?jsp=/app/rest/server;.jsp` từ phía kẻ tấn công.
- Sau đó mìnnh tiếp tục vào HTTP Stream để xem chi tiết phần nội dung XML phản hồi từ máy chủ và thấy dòng khai báo `<server version="2023.11.3 (build 147512)" ...>`.


### Q3: After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?
- Từ kết quả ở câu 2, mình xác định dịch vụ web đang chạy là **JetBrains TeamCity** phiên bản `2023.11.3`.
- Đối chiếu phiên bản này với hành vi khai thác quan sát được trong tệp PCAP — cụ thể là việc kẻ tấn công gửi các yêu cầu chứa đường dẫn đặc biệt dạng `/hax?jsp=/app/rest/server;.jsp`, `/hax?jsp=/app/rest/users;.jsp` và tạo trái phép API token qua `/hax?jsp=/app/rest/users/id:2/tokens/mD5r0yenB0;.jsp` mà không cần đăng nhập— mình tra cứu và xác định đây là kỹ thuật khai thác lỗ hổng vượt qua xác thực (Authentication Bypass) và CVE tương ứng với lỗ hổng này là `CVE-2024-27198`.

### Q4: What credentials did the attacker successfully use for Basic Auth against the TeamCity server?

- Để tìm thông tin tài khoản mà kẻ tấn công đã tạo và sử dụng để xác thực với máy chủ TeamCity, mình dùng bộ lọc `ip.src == 23.158.56.196 && http.request.method == POST` trên Wireshark nhằm liệt kê toàn bộ các yêu cầu gửi dữ liệu xuất phát từ IP của kẻ tấn công.

<img width="1917" height="857" alt="image" src="https://github.com/user-attachments/assets/2b716f9d-b26a-483a-a3be-983888ceee08" />

- Quan sát danh sách các gói tin theo trình tự thời gian, mình phát hiện yêu cầu `POST /hax?jsp=/app/rest/users;.jsp` dùng để khai thác API tạo người dùng mới.

- Sau đó mình tiếp tục xem chi tiết qua HTTP Stream thì phát hiện `username` là `c91oyemw` và `password` là `CL5vzdwLuK`.

<img width="1238" height="65" alt="image" src="https://github.com/user-attachments/assets/b3b939d1-cf77-4b81-90b8-18e6d550b0ec" />

### Q5: The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?

- Mình tiếp tục sử dụng bộ lọc `ip.addr == 23.158.56.196 && http.request.method == POST` và mình phát hiện ngay sau bước tạo tài khoản và sinh API token, kẻ tấn công đã gửi một yêu cầu `POST /admin/pluginUpload.html` (gói tin số `24825`) chứa dữ liệu nén (`application/zip`) lên máy chủ TeamCity.

<img width="1907" height="470" alt="image" src="https://github.com/user-attachments/assets/3696cb98-92d5-4d46-9561-75d0b023520e" />

- Sau đó mình xem tiếp chi tiết gói tin ở phần MIME Multipart Media Encapsulation tại trường filename có giá trị là `NSt8bHTg.zip`

<img width="1527" height="677" alt="image" src="https://github.com/user-attachments/assets/ffcaa5fe-589b-4bb9-bff0-46e3299227a6" />

### Q6: When did the attacker execute their first command via the web shell?

- Mình tiếp tục sử dụng bộ lọc `ip.addr == 23.158.56.196 && http.request.method == POST`, mình quan sát các gói tin ngay sau thời điểm kẻ tấn công kích hoạt plugin độc hại.
- Tại gói tin số `25572` (`POST /plugins/NSt8bHTg/NSt8bHTg.jsp`), kiểm tra phần dữ liệu gửi đi (`application/x-www-form-urlencoded`) ở khung giải mã ASCII bên dưới, mình phát hiện kẻ tấn công đã thực thi câu lệnh đầu tiên là `cmd=ls`.

<img width="1916" height="852" alt="image" src="https://github.com/user-attachments/assets/ddf7531e-e25c-4f1b-8173-ff19dcd77933" />

- Sau đó tại UTC Arrival Time, mình ghi nhận thời điểm gói tin này đến máy chủ là `Jun 30, 2024 08:03:57.620161000 UTC`.

<img width="863" height="442" alt="image" src="https://github.com/user-attachments/assets/329ef6c5-fb52-4a3f-9257-9c0574725402" />


### Q7: The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?

- Mình sẽ tiếp tục theo dõi chuỗi yêu cầu gửi tới webshell bằng bộ lọc `ip.src == 23.158.56.196 && http.request.uri contains "NSt8bHTg.jsp"`.

<img width="1906" height="815" alt="image" src="https://github.com/user-attachments/assets/a779eab3-420d-4834-a033-34a8e2f1890c" />


- Tại gói tin số `31123`, phần dữ liệu thô hiển thị rõ chuỗi lệnh mã hóa URL: `cmd=bash+-c+%27echo+%22username%3Aa1l4m%2Cpassword%3Ayouarecompromised%22+%3E+%2Ftmp%2Fcreds.txt%27`

- Sau đó mình vào HTTP Stream để xem đầy đủ thì dòng lệnh là `cmd=bash+-c+%27echo+%22username%3Aa1l4m%2Cpassword%3Ayouarecompromised%22+%3E+%2Ftmp%2FCreds.txt%27`

- Giải mã bằng CyberChef chuỗi trên thành `bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/creds.txt'`, mình xác định kẻ tấn công đã ghi đè tệp `/tmp/creds.txt` bằng tài khoản mới có tên đăng nhập `a1l4m` và mật khẩu `youarecompromised`.

### Q8: Q7 showed the attacker writing false credentials into Creds.txt. Which MITRE ATT&CK sub-technique (Data Manipulation family) describes that specific file-write action?

- Từ kết quả phân tích ở Q7 (gói tin `31123`), kẻ tấn công đã thực thi lệnh ghi đè cặp tài khoản giả `username:a1l4m,password:youarecompromised` vào tệp `/tmp/creds.txt` lưu trữ trên đĩa của máy chủ.

- Mình đối chiếu với khung tham chiếu **MITRE ATT&CK** trong nhóm kỹ thuật **Data Manipulation (`T1565`)**, hành vi chỉnh sửa hoặc ghi đè dữ liệu tĩnh đang lưu trên hệ thống tệp/ổ đĩa nhằm làm sai lệch thông tin được phân loại vào kỹ thuật con **`T1565.001` (Stored Data Manipulation)**.

<img width="1910" height="907" alt="image" src="https://github.com/user-attachments/assets/fc8387bb-2a10-40c6-a574-33b51e31705f" />


### Q9: Immediately after gaining a shell, the attacker executed a docker command that mounted the host filesystem and chrooted into it — providing full host access. What was that exact command? (Do NOT include the cmd= prefix seen in the HTTP body.)
- Tiếp tục kiểm tra các luồng yêu cầu gửi tới webshell qua các gói tin tiếp theo, mình xác định luồng HTTP chứa thao tác container  tại `tcp.stream eq 601` tương ứng gói tin số `32137`

<img width="1915" height="815" alt="image" src="https://github.com/user-attachments/assets/8e5431e4-f0f2-4a65-ae97-21bcd90cf287" />

- Sau đó mình tiếp tục xem Stream HTTP thì thấy được một tham số mã hóa URL theo yêu cầu đề bài là `cmd=docker+run+--rm+-it+-v+%2F%3A%2Fhost+ubuntu+chroot+%2Fhost`

<img width="1252" height="445" alt="image" src="https://github.com/user-attachments/assets/726770bf-ef12-4ef8-b69b-d7e6643f3ab9" />

- Sau khi giải mã bằng CyberChef thì mình nhận được lệnh hoàn chỉnh mà kẻ tấn công đã sử dụng là `docker run --rm -it -v /:/host ubuntu chroot /host`
