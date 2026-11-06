# LGDroid Lab
## 1. Bối cảnh
Vào ngày 21/05/2021, cơ quan chức năng đã trích xuất toàn bộ ổ đĩa của một thiết bị di động LG bị tình nghi sử dụng trong các hoạt động bí mật. Nhiệm vụ của mình là phân tích các cơ sở dữ liệu SQLite, log hệ thống và artifact ứng dụng để dựng lại hoạt động của người dùng, xác định các kết nối mạng và thiết lập mốc thời gian chi tiết cho sự cố.

Các công cụ chính: DB Browser for SQLite, Python, Epoch Converters.

## 2. Điều tra
### Q1: What is the email address of Zoe Washburne?
- Để tìm kiếm thông tin liên lạc của các đối tượng trong danh bạ, mình tiến hành kiểm tra các cơ sở dữ liệu SQLite được trích xuất từ phân vùng hệ thống ứng dụng, cụ thể là file chứa dữ liệu danh bạ `contacts3.db`
- Mình sử dụng công cụ DB Browser for SQLite để mở và phân tích cấu trúc bảng dữ liệu bên trong file và mình trích xuất thành công địa chỉ email liên kết với tài khoản này là `zoewash@0x42.null`

### Q2: What was the device's DateTime in UTC at the time of acquisition?
- Để xác định mốc thời gian chính xác của thiết bị tại thời điểm trích xuất dữ liệu, mình kiểm tra thư mục chứa các artifact thu thập từ hệ thống đang chạy `Live Data`.

- Trong thư mục Live Data, mình tìm thấy file văn bản device_datetime_utc.txt dùng để ghi lại thông tin thời gian hệ thống dưới dạng chuẩn UTC, sau đó mình trích xuất được mốc thời gian UTC là `2021-05-21 18:17`

### Q3: What time was the Tor Browser downloaded in UTC?

- Để xác định thời điểm tải về của trình duyệt Tor trên hệ điều hành Android, mình truy cập vào cơ sở dữ liệu quản lý các tệp đã tải xuống tại file `downloads.db`.
- Mình mở downloads.db bằng công cụ DB Browser for SQLite,  và chọn bảng downloads
- Sau đó mình tìm thấy đường dẫn ` /storage/emulated/0/Download/tor-browser-10.0.15-android-armv7-multi.apk`. Tại đây mình cũng thấy được cột lastmod có giá trị là `1619725346000`.

<img width="1285" height="438" alt="image" src="https://github.com/user-attachments/assets/ba8e1bc0-85f1-408b-bfa0-9ceb81547435" />

- Mình ử dụng công cụ Epoch Converter để quy đổi giá trị mili-giây trên sang định dạng thời gian chuẩn UTC thì thu được kết quả là `2021-04-29 19:42`

### Q4: At what time did the phone reach a 100% charge after the last reset?
- Để tính toán thời điểm thiết bị đạt mức sạc 100%, mình tiến hành phân tích file nhật ký batterystats.txt để trích xuất các mốc thời gian liên quan đến trạng thái pin.
- Đầu tiên, mình thấy thời gian thiết lập lại trạng thái thống kê pin (RESET:TIME) trong file log được ghi nhận tại: `2021-05-21-13-12-19`

<img width="1320" height="112" alt="image" src="https://github.com/user-attachments/assets/bcf926e5-2cb9-4c1c-8869-51618c9f48e4" />

- Tiếp theo, mình tìm kiếm sự kiện thiết bị hoàn tất quá trình sạc đầy pin (status=full charge), bản ghi lưu trữ khoảng thời gian lệch (offset) so với mốc reset gốc là ` +5m01s459ms (3) 100 status=full charge=2665` 

<img width="582" height="142" alt="image" src="https://github.com/user-attachments/assets/52099ace-1042-43ef-9f4b-9acfe1afbc2d" />

- Cộng khoảng thời gian lệch 5 phút 01 giây 459 mili-giây vào mốc RESET:TIME, ta xác định được thời điểm chính xác thiết bị đạt 100% pin là `2021-05-21 13:17:20`

### Q5: What is the password for the most recently connected WIFI access point?

- Để tìm thông tin cấu hình mạng Wi-Fi và mật khẩu được lưu trên thiết bị Android, mình tiến hành kiểm tra các tệp cấu hình của hệ thống quản lý cài đặt (Settings Provider).
- Mình phát hiện được các tệp tin cấu hình và bản sao lưu hệ thống (như tệp sao lưu Wi-Fi wifi_new_config hoặc dữ liệu bên trong cấu hình WifiBackupData) chứa danh sách chi tiết các mạng đã từng kết nối.
- Mình mở và phân tích cấu trúc khối mạng (NetworkList), sau đó tìm đến thẻ cấu hình WifiConfiguration. Tại đây, thông tin tên mạng hiển thị tại trường <string name="SSID"> và khóa bảo mật được mã hóa tương ứng của mạng này được lưu trữ trực tiếp tại trường <string name="PreSharedKey">. Mình trích xuất và thu được password là `ThinkingForest!`

<img width="685" height="371" alt="image" src="https://github.com/user-attachments/assets/c3340e50-c688-41ad-ba5e-1372fc40b3e8" />

### Q6: What app was the user focused on at 2021-05-20 14:13:27?

- Để xác định ứng dụng mà người dùng đang tập trung tương tác (foreground) tại mốc thời gian 2021-05-20 14:13:27, mình kiểm tra nhật ký sự kiện sử dụng ứng dụng usage_stats.txt trong thư mục Live Data/
- Mình quan sát đoạn log chi tiết xung quanh mốc thời gian yêu cầu và thấy vào lúc 14:13:27, hệ thống ghi nhận đồng thời hai sự kiện quan trọng:

  -  time="2021-05-20 14:13:27" type=MOVE_TO_BACKGROUND package=com.lge.launcher3: Trình khởi chạy màn hình chính (com.lge.launcher3) chuyển xuống nền.

  -  time="2021-05-20 14:13:27" type=MOVE_TO_FOREGROUND package=com.google.android.youtube: Ứng dụng YouTube (com.google.android.youtube) chính thức chuyển lên giao diện chính (foreground) ngay tại thời điểm đó.
 Đáp án ` youtube`

<img width="1387" height="302" alt="image" src="https://github.com/user-attachments/assets/4c334697-6745-431f-96a8-d44497998c44" />


### Q7: How long did the suspect watch YouTube on 2021-05-20?

- Để tính tổng thời gian người dùng xem YouTube trong ngày 2021-05-20, mình sẽ trích xuất và lọc toàn bộ các cặp sự kiện MOVE_TO_FOREGROUND và MOVE_TO_BACKGROUND của gói ứng dụng com.google.android.youtube từ file usage_stats.txt.
- Mình ghi nhận được các mốc thời gian như sau:
  - Bắt đầu phiên xem: 2021-05-20 14:13:27 (với WatchWhileActivity)
  - Kết thúc phiên xem : 2021-05-20 15:13:27 (ghi nhận qua sự kiện chuyển đổi STANDBY_BUCKET_CHANGED ).

<img width="1442" height="265" alt="image" src="https://github.com/user-attachments/assets/6a112a18-6a5b-436e-b1e9-5c71929034b8" />

- Như vậy tổng thời gian sử dùng youtube được tính là ` 08:34`


