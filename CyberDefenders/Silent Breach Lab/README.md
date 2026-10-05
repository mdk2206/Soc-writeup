# Silent Breach Lab

## Bối cảnh 

- Tổ chức IMF bị tấn công mạng. Ethan đã tải dữ liệu từ một máy chủ bị xâm nhập, nhưng sau đó toàn bộ tệp tin đã bị mã hóa không thể đọc được. Nhiệm vụ của chúng ta là phân tích file chứng cứ để điều tra hành vi mã độc và tìm cách giải mã dữ liệu

## Điều tra

### Câu 1: What is the MD5 hash of the potentially malicious EXE file the user downloaded?

- Đầu tiên mình sử dụng công cụ FTK Imager để load file forensic image của bài Lab.
- Dựa vào bối cảnh cho biết người dùng đã tải xuống dữ liệu, mình tập trung kiểm tra thư mục chứa file tải về mặc định.Ở mục Downloads mình phát hiện thấy 1 file exe đáng nghi có tên là IMF-Info.pdf.exe

<img width="381" height="358" alt="image" src="https://github.com/user-attachments/assets/4ad6c62f-fe31-4680-906a-55d3ff8870e3" />

- Sau đó mình trích xuất mã hash của file bằng Properties thì thu được:  336a7cf476ebc7548c93507339196abb

<img width="907" height="427" alt="image" src="https://github.com/user-attachments/assets/5e7f00d5-88ae-466a-93ef-f44f6eaf1d5a" />

<img width="990" height="192" alt="image" src="https://github.com/user-attachments/assets/87e142b9-706e-436a-aef0-2d785cde17e9" />

### Câu 2: What is the URL from which the file was downloaded?

- Vì khi một file được tải về từ Internet thông qua trình duyệt hoặc ứng dụng, hệ thống sẽ tự động gán thêm một luồng dữ liệu phụ gọi là Zone.Identifier để cho biết nguồn gốc của file

<img width="1122" height="437" alt="image" src="https://github.com/user-attachments/assets/9a5e2123-b57f-4a93-9fc8-e0a1c0a0f10a" />

- Sau khi xem file Zone.identifier thì mình trích xuất được URL mà tệp tin được tải xuống là:http://192.168.16.128:8000/IMF-Info.pdf.exe

<img width="992" height="180" alt="image" src="https://github.com/user-attachments/assets/524da8e2-efa0-46b1-a152-ebbfc2b55981" />

### Câu 3: What application did the user use to download this file?

- Để xác định ứng dụng nạn nhân dùng để tải tệp độc hại, mình trích xuất tệp cơ sở dữ liệu lịch sử duyệt web History từ đường dẫn hồ sơ người dùng: AppData\Local\Microsoft\Edge\User Data\Default\History

 <img width="1477" height="792" alt="image" src="https://github.com/user-attachments/assets/e8f66e35-028e-453d-9958-1395e7b5bc5e" />
 
- Sau đó mình mở tệp History trên SQLite Viewer và vào mục downloads thì phát hiện thấy người dùng đã tải file IMF-Info.pdf.exe

<img width="1383" height="463" alt="image" src="https://github.com/user-attachments/assets/4375e12d-d177-4636-8997-da84007fdc25" />

- Vì vậy mình kết luận ứng dụng người dùng đã sử dụng để tải tệp tin này là: Microsoft Edge

<img width="1002" height="172" alt="image" src="https://github.com/user-attachments/assets/59ee340f-9fa1-41b5-80ae-45f8c108bfb4" />


### Câu 4: By examining Windows Mail artifacts, we found an email address mentioning three IP addresses of servers that are at risk or compromised. What are the IP addresses?

- Mình tìm theo kiến trúc lưu trữ của Windows Mail, cơ sở dữ liệu và bản ghi email được lưu tại file HxStore.hxd trong thư mục Users\ethan\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState

 <img width="1680" height="795" alt="image" src="https://github.com/user-attachments/assets/2f207519-8db1-4f2f-a0da-e2e1850950c5" />

- Vì HxStore.hxd là file nhị phân nên mình sẽ sử dụng strings.exe cũng với powershell để trích xuất những chuỗi có định dạng IPv4

<img width="1460" height="255" alt="image" src="https://github.com/user-attachments/assets/08e0978e-fe8c-40ba-8949-c695d1712af5" />

- Mình trích xuất được ba địa chỉ IP được đề cập trong email là:145.67.29.88,   212.33.10.112,    192.168.16.128

<img width="996" height="207" alt="image" src="https://github.com/user-attachments/assets/65163ef4-6df9-425a-bd47-83b6c3411fef" />

### Câu 5: By examining the malicious executable, we found that it uses an obfuscated PowerShell script to decrypt specific files. What predefined password does the script use for encryption?

- Đầu tiên mình sử dụng FTK Imager xuất tệp thực thi độc hại từ forensic image ra môi trường ngoài.
- Sau đó mình dùng strings.exe quét toàn bộ chuỗi văn bản bên trong tệp nhị phân và lưu ra tệp văn bản để tiện phân tích:

<img width="535" height="27" alt="image" src="https://github.com/user-attachments/assets/05939218-6fa3-4bc5-aa9a-634bbbc1dcb8" />

- Vì đề bài yêu cầu liên quan đến chuỗi PowerShell script nên mình sẽ tìm kiếm theo từ khóa powershell trong file malware_strings.txt

<img width="1670" height="298" alt="image" src="https://github.com/user-attachments/assets/8c0fc87a-329b-4e22-9060-ae40a143a60a" />

- Dấu hiệu để mình khẳng định đây là script powershell mà kẻ tấn công sử dụng là vì nó có powershell.exe -ExecutionPolicy Bypass -File kèm các từ khóa mã hóa/giải mã khác như TocharArray, Base64,....

- Tiếp theo mình tiến hành copy chuỗi đó và dán ra file solve.ps1
- Nhìn thấy dòng lệnh cuối cùng gọi hàm thực thi (pwn $FHG7xpKlVqaDNgu1c2Utw) nên mình sẽ thay thế lệnh này bằng Write-Output để chỉ in ra nội dung mã nguồn gốc mà không kích hoạt tiến trình độc hại
- Sau đó thực hiện chạy file bằng lệnh  powershell.exe -ExecutionPolicy Bypass -File .\solve.ps1

<img width="863" height="605" alt="image" src="https://github.com/user-attachments/assets/75c65ad6-ad97-41d6-9f41-784ba69ab399" />

- Quan sát mình thấy được chuỗi password mà kẻ tấn công dùng chính là Imf!nfo#2025Sec$

<img width="1007" height="212" alt="image" src="https://github.com/user-attachments/assets/5175f4d0-da42-4f80-a761-4323b6318c0d" />


### Câu 6: After identifying how the script works, decrypt the files and submit the secret string.

- Theo kết quả từ câu 5 thì mình thấy rằng có 2 file bị mã hóa đó chính là C:\\Users\\ethan\\Desktop\\IMF-Secret.pdf","C:\\Users\\ethan\\Desktop\\IMF-Mission.pdf"
- Mình sẽ lần theo đường dẫn này trong FTK và phát hiện chúng đã bị mã hóa thành đuôi .enc

<img width="213" height="162" alt="image" src="https://github.com/user-attachments/assets/7294ea0c-edb5-4214-b2c7-2c805b241ca1" />


- Sau đó mình trích xuất 2 file này ra ngoài thư mục phân tích
- Tiếp đến mình sẽ tạo tệp decrypt.ps1 bằng cách tái sử dụng khối tạo khóa dẫn xuất ở câu 5 và chỉnh sửa các thành phần mã hóa thành giải mã:

<img width="1362" height="787" alt="image" src="https://github.com/user-attachments/assets/991d8204-a457-40a0-af7d-9e8a81630a91" />

- Những điểm thay đổi giữa decrupt.ps1 so với script gốc của mã độc mã mình sử dụng là:

     Thay $aes.CreateEncryptor() thành $aes.CreateDecryptor().
  
     Đổi logic thay thế từ \.pdf$ $\rightarrow$ .enc thành \.enc$ $\rightarrow$ _decrypted.pdf.
  
     Đọc các byte đã mã hóa ($cipherBytes) thay vì byte văn bản gốc ($plainBytes).
  
     Loại bỏ hoàn toàn lệnh xóa file Remove-Item $inputFile -Force để bảo toàn file gốc

- Tiếp theo mình sẽ chạy lệnh giải mã

<img width="562" height="77" alt="image" src="https://github.com/user-attachments/assets/35e5e6af-c618-46d3-b991-b6dd324c4e25" />

- Cuối cùng mình sẽ mở các file đã giải mã để xem flag

<img width="808" height="710" alt="image" src="https://github.com/user-attachments/assets/5ef6e721-32b7-41bc-8abc-054db3e56069" />

- Flag của bài này chính là CyberDefenders{N3v3r_eX3cuTe_F!l3$_dOwnL0ded_fr0m_M@lic10u5_$erV3r} 

<img width="1010" height="207" alt="image" src="https://github.com/user-attachments/assets/d254fb19-126d-4a8c-bd10-7a553001f586" />
