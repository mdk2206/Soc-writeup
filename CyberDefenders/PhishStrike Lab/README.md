# PhishStrike Lab

## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố phishing tại một cơ sở giáo dục. Đội an ninh mạng nhận được cảnh báo về một email lừa đảo nhắm vào các giảng viên. Email giả danh một liên hệ đáng tin cậy, thông báo về một giao dịch mua trị giá 625.000 USD và cung cấp đường link để tải hóa đơn, nhằm đánh vào tâm lý lo lắng của người nhận.

Nhiệm vụ của mình là đóng vai chuyên viên phân tích: dùng các công cụ threat intelligence để điều tra email, phân tích header để xác định nguồn gửi thật, kiểm tra đường link xem có chứa nội dung độc hại hay không, từ đó trích xuất các IOCs và ghi lại kết quả để ngăn chặn gian lận và hướng dẫn giảng viên nhận biết phishing.

## 2. Điều tra

### Q1: Identifying the sender's IP address with specific SPF and DKIM values helps trace the source of the phishing email. What is the sender's IP address that has an SPF value of softfail and a DKIM value of fail?

- Mình mở file email bằng Notepad  và tìm các trường xác thực trong header. Dòng `Authentication-Results` ghi `spf=softfail (sender IP is 18.208.22.104)` và `dkim=fail (no key for signature)` với `header.d=uptc.edu.co`. Dòng `Received-SPF` cũng ghi SoftFail cho cùng địa chỉ IP này.

<img width="706" height="177" alt="image" src="https://github.com/user-attachments/assets/a36f2387-65cf-478e-be3b-8cf4459c3dcd" />

- Đối chiếu với các dòng `Received`, IP `18.208.22.104` ứng với `inpost.tmes.trendmicro.com`, tức máy chủ của dịch vụ lọc thư Trend Micro chuyển tiếp thư tới Outlook. Như vậy domain `uptc.edu.co` không ủy quyền cho IP này gửi thư (SPF softfail) và chữ ký DKIM không xác minh được, hai dấu hiệu cho thấy thư có thể bị giả mạo người gửi.

**Đáp án:** `18.208.22.104`

### Q2: Understanding the return path of an email is essential for tracing its origin. What is the return path specified in this email?

- Mình tiếp tục tìm trường `Return-Path` trong header. Trường này cho biết địa chỉ nhận thư trả về khi thư không gửi được, giá trị là **erikajohana.lopez@uptc.edu.co**.

<img width="612" height="82" alt="image" src="https://github.com/user-attachments/assets/ec617ecb-3ae9-4e99-9268-abd957785502" />


### Q3: Identifying the source of malware is critical for effective threat mitigation and response. What is the IP address of the server hosting the malicious file related to malware distribution?

- Mình tiếp tục tìm thấy đường link dẫn tới "hóa đơn". Thẻ `<a>` trỏ tới `http://107.175.247.199/loader/install.exe`.

<img width="1401" height="163" alt="image" src="https://github.com/user-attachments/assets/c982d4d9-c763-4d24-9a74-c4e53c5cc53b" />

### Q4: Identifying malware that exploits system resources for cryptocurrency mining is critical for prioritizing threat mitigation efforts. The malicious URL can deliver several malware types. Which malware family is responsible for cryptocurrency mining?

- Từ câu 3, URL trong email là `http://107.175.247.199/loader/install.exe`. Mình tra host `107.175.247.199` trên URLhaus , mục Malware URLs, và thấy đúng URL này được gắn ba nhãn: AsyncRAT, BitRAT và **CoinMiner**.

<img width="1626" height="577" alt="image" src="https://github.com/user-attachments/assets/9f8b3297-a9f8-4002-96cb-f9a6becb9a07" />


- Trong các họ trên, AsyncRAT và BitRAT là mã độc điều khiển từ xa, còn `CoinMiner` chính là mã độc đào tiền mã hóa.

### Q5: Identifying the specific URLs malware requests is key to disrupting its communication channels and reducing its impact. Based on the previous analysis of the cryptocurrency malware sample, what does this malware request the URL?

- Từ câu 4, mẫu CoinMiner có SHA256 `453fb1c4b3b48361fa8a67dcedf1eaec39449cb5a146a7770c63d1dc0d7562f0`. Mình tra hash này trên VirusTotal,tại mục Contacted URLs mình thấy có hai URL bị 13/95 engine gắn cờ độc hại: `http://107.175.247.199/loader/server.exe` và `http://ripley.studio/loader/uploads/Qanjttrbv.jpeg`.

<img width="872" height="232" alt="image" src="https://github.com/user-attachments/assets/b5b86aca-4ecc-4b97-97b4-6488323ce8cb" />

- URL `server.exe` thuộc cùng máy chủ phát tán đã gắn nhãn BitRAT ở câu 4. URL còn lại nằm trên tên miền khác (`ripley.studio`), trong thư mục `uploads` với tên file ngẫu nhiên và đuôi ảnh, là kiểu đường dẫn dùng để tải payload giai đoạn hai. Vì vậy mình xác định URL mẫu yêu cầu là **http://ripley.studio/loader/uploads/Qanjttrbv.jpeg**.


### Q6: Understanding the registry entries added to the auto-run key by malware is crucial for identifying its persistence mechanisms. Based on the BitRAT malware sample analysis, what is the executable's name in the first value added to the registry auto-run key?

- Mình tiếp tục dùng kết quả của URLhaus và lấy SHA256 của payload có signature BitRAT sau đó tra trên VirusTotal. Tại mục Registry Keys Set mình phát hiện giá trị được thêm vào khóa `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` có tên là `Jzwvix` đồng thời tên file thực thi là **Jzwvix.exe**. Khóa Run khiến file này tự chạy mỗi lần người dùng đăng nhập, là cơ chế duy trì truy cập của BitRAT.

<img width="758" height="90" alt="image" src="https://github.com/user-attachments/assets/513bda68-841d-4b79-9f95-801000d95119" />

### Q7: Identifying the SHA-256 hash of files downloaded from a malicious URL is essential for tracking and analyzing malware activity. Based on the BitRAT analysis, what is the SHA-256 hash of the file previously downloaded and added to the autorun keys?

- Ở câu trước, ta đã xác định được tệp thực thi mã độc dùng để thiết lập cơ chế duy trì quyền truy cập thông qua khóa autorun là Jzwvix.exe.

- Sau đó mình chuyển sang phần Files Dropped và tiến hành rà soát danh sách và tìm thấy đường dẫn chính xác của tệp thực thi này nằm tại thư mục người dùng:C:\Users\user\AppData\Roaming\Ozndcoodb\Jzwvix.exe. Đồng thời tìm được mã hash là ` bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539 ` .

<img width="1001" height="205" alt="image" src="https://github.com/user-attachments/assets/7675974c-a5a9-450f-a1cf-3b5e3a21b7da" />



### Q8: Analyzing the HTTP requests made by malware helps in identifying its communication patterns. What is the URL in the HTTP request used by the loader to retrieve the BitRAT malware?

- Ở câu này mình tiếp tục vào phần Network Communication trên VirusTotal để điều tra các luồng giao tiếp mạng do tệp mồi tạo ra.

- Sau đó, mình phát hiện một yêu cầu ` GET http://107.175.247.199/loader/server.exe 200 ` lén lút mà trình tải đã sử dụng để kéo tệp thực thi server.exe về máy. Yêu cầu này ghi nhận rõ ràng URL trỏ trực tiếp đến máy chủ của kẻ tấn công  107.175.247.199 đã tìm thấy ở Q3.

### Q9: Introducing a delay in malware execution can help evade detection mechanisms. What is the delay (in seconds) caused by the PowerShell command according to the BitRAT analysis?

- Phân tích lệnh PowerShell: Khi kiểm tra phần Process Tree trên VirusTotal, mình phát hiện mã độc có gọi một tiến trình PowerShell kèm theo tham số -enc. Kẻ tấn công thường dùng tham số này để chạy các đoạn mã đã được mã hóa Base64 nhằm trốn tránh các công cụ giám sát bảo mật.

<img width="1277" height="170" alt="image" src="https://github.com/user-attachments/assets/99ed9832-8224-4f8f-9f80-e2cf3798704c" />

- Sau khi đưa đoạn base64 lên CyberChef để giải mã thì mình thu được đoạn lệnh là ` Start-Sleep -Seconds 50` đồng nghĩa với việc thời gian trì hoãn là ` 50 `.

### Q10: Tracking the command and control (C2) domains used by malware is essential for detecting and blocking malicious activities. What is the C2 domain used by the BitRAT malware?
- Khi rà soát phần lưu lượng mạng tự động (như Contacted Domains) trên tab Behavior của VirusTotal, mình nhận thấy thông tin C2 có thể bị thiếu hoặc nhiễu. Vì vậy mình chuyển sang tab Community để tra cứu các báo cáo phân tích sâu từ các chuyên gia bảo mật và nền tảng Threat Intelligence và thu được C2 là `  gh9st.mywire.org`

<img width="591" height="346" alt="image" src="https://github.com/user-attachments/assets/7d08f25b-aea2-423d-8f63-7bdf17de500c" />

### Q11: Understanding how malware exfiltrates data is essential for detecting and preventing data breaches. According to the AsyncRAT analysis, what is the Telegram Bot ID used by this malware?

- Để mở rộng điều tra về cơ chế đánh cắp dữ liệu, mình tiến hành phân tích mẫu AsyncRAT dựa trên báo cáo sandbox của nền tảng Hatching Triage.
- Mình kiểm tra mục Network để rà soát các luồng HTTP GET requests. Đáng chú ý là mã độc này không gửi dữ liệu ăn cắp thẳng về máy chủ C2, mà lại lạm dụng nền tảng nhắn tin Telegram để ngụy trang lưu lượng. Quan sát tiếp URL thì mình thu được ID của Bot Telegram là `bot5610920260`

<img width="1348" height="257" alt="image" src="https://github.com/user-attachments/assets/ee92ec70-cf0a-46b8-b066-4567ea20b804" />

  


