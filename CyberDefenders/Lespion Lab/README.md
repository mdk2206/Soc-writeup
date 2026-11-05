# Lespion Lab
## 1. Bối cảnh
- Bài Lab mô phỏng sự cố mạng doanh nghiệp bị xâm nhập và ngắt kết nối. Đội ứng cứu sơ bộ xác định cuộc tấn công xuất phát từ một tài khoản người dùng, nghi ngờ có kẻ nội gián (insider threat).

- Nhiệm vụ của mình là phân tích các chứng cứ số và dữ liệu OSINT để tìm ra danh tính kẻ nội gián, đồng thời vạch trần toàn bộ chuỗi hành vi xâm nhập.

## 2. Điều tra

### Q1: File -> Github.txt: What API key did the insider add to his GitHub repositories?

- Mình mở file Github.txt được cung cấp trong gói artifact của bài lab và tìm thấy đường dẫn tài khoản GitHub của nghi phạm:`https://github.com/EMarseille99`
- Khi xem qua các repository công khai của tài khoản này, mình phát hiện dự án Project-Build---Custom-Login-Page. Bên trong repository này chứa file mã nguồn Login Page.js, và ở phần đầu của file mã nguồn có chứa chuỗi API key mà kẻ nội gián đã thêm vào.

<img width="1586" height="762" alt="image" src="https://github.com/user-attachments/assets/e45313d9-7e56-4818-b427-e694f1aa8fb4" />

Đáp án: `aJFRaLHjMXvYZgLPwiJkroYLGRkNBW`

### Q2: File -> Github.txt: What plaintext password did the insider add to his GitHub repositories?

- Cũng tiếp tục trong file mã nguồn Login Page.js, mình phát hiện thấy một password được mã hóa bằng Base64, sau đó mình dùng CyberChef để giải mã thì thu được password là `PicassoBaguette99`

<img width="810" height="192" alt="image" src="https://github.com/user-attachments/assets/a891a114-f511-49d9-92a3-885d542eed87" />

<img width="1567" height="497" alt="image" src="https://github.com/user-attachments/assets/e6793017-5c70-475a-b2d0-3c99e10d7440" />

### Q3: File -> Github.txt: What cryptocurrency mining tool did the insider use?

- Tiếp tục kiểm tra danh sách các repository public trên tài khoản GitHub của nghi phạm mình tìm thấy một repository được fork về có tên là xmrig.

<img width="1917" height="912" alt="image" src="https://github.com/user-attachments/assets/ac49f438-e88b-44d9-81e4-7ee8295e7153" />

- Sau đó mình có tìm hiểu được XMRig là một công cụ mã nguồn mở phổ biến chuyên dùng để đào tiền điện tử (Cryptocurrency Mining) như Monero (XMR). Việc xuất hiện repository này trên tài khoản của nghi phạm cho thấy công cụ mà kẻ nội gián đã sử dụng hoặc chuẩn bị để khai thác trái phép tài nguyên hệ thống.

Đáp án: `XMRig`

### Q4: On which gaming website did the insider have an account?

- Để truy vết tài khoản game của nghi phạm, mình tiếp tục điều tra tài khoản Instagram của đối tượng `https://www.instagram.com/EMarseille99`
- Tại đây mình phát hiện 1 mã qr code, sau đó mình tiến hành quét mã này thì liên kết trả về đưa trực tiếp tới trang hồ sơ cá nhân trên nền tảng chơi game Steam.

<img width="1307" height="881" alt="image" src="https://github.com/user-attachments/assets/90132882-2a01-4740-bfde-8474dba95144" />

Đáp án: `steam`

### Q5: What is the link to the insider Instagram profile?
- Theo như câu 4 thì mình có được liên kết đến instagram của nghi phạm là ` https://www.instagram.com/EMarseille99/`

### Q6: Which country did the insider visit on her holiday?

- Mình tiếp tục tìm trên instargram của nghi phạm thì tìm được cô ấy vừa đến ` Singapore`
- 
### Q7: Which city does the insider family live in?

- Tương tự như câu 6 thì mình cũng tìm được gia đình cô ấy đang sống tại `Dubai`

### Q8: File -> office.jpg: You have been provided with a picture of the building in which the company has an office. Which city is the company located in?
- Từ thông tin bức ảnh `office.jpg` mà đề cung cấp mình tìm kiếm trên Google thì biết được nơi đó chính là `Birmingham` , Vương Quốc Anh

### Q9: File -> Webcam.png: With the intel, you have provided, our ground surveillance unit is now overlooking the person of interest suspected address. They saw them leaving their apartment and followed them to the airport. Their plane took off and landed in another country. Our intelligence team spotted the target with this IP camera. Which state is this camera in?
- Cũng tương tự như câu 8 thì mình tìm được nơi đó chính là `Notre Dam`  Indiana
