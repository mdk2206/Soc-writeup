# MalDoc101 Lab

## 1. Bối cảnh 

Kẻ tấn công thường dùng các kỹ thuật living-off-the-land (LOTL), ví dụ chạy PowerShell, để tiến xa hơn trong cuộc tấn công và tránh phụ thuộc vào mã macro truyền thống. Bài Lab nhằm minh họa cách phân tích nhanh các artifact để trích xuất các chỉ số xâm phạm (IOCs) quan trọng, với trọng tâm là các kỹ thuật phân tích tĩnh.

Nhiệm vụ của mình là đóng vai chuyên viên blue team: phân tích các script bị làm rối để xác định hạ tầng độc hại, cụ thể là tên miền đầu tiên (FQDN) được dùng để tải một trojan, từ đó nâng cao kỹ năng săn tìm mối đe dọa và ứng phó sự cố. Công cụ sử dụng trong bài: REMnux, Terminal với Python, oledump, olevba, Text Editor.

## 2. Điều tra

### Q1: Multiple streams contain macros in this document. Provide the number of the highest one.

- Ở câu này mình sẽ chạy công cụ `oledump.py` (`python oledump.py .\sample.bin`) để liệt kê danh sách các luồng dữ liệu OLE bên trong tài liệu.

<img width="752" height="582" alt="image" src="https://github.com/user-attachments/assets/0412529d-90d8-4e27-98c8-0f98b46a4c6e" />

- Kiểm tra các luồng mang ký hiệu macro (`M` và `m`), mình ghi nhận được các luồng `13` (`Macros/VBA/diakzouxchouz`), `15` (`Macros/VBA/govwiahtoozfaid`) và `16` (`Macros/VBA/roubhaol`), trong đó luồng có số thứ tự cao nhất là `16`.

### Q2: What event is used to begin the execution of the macros?

- Từ danh sách các luồng macro ở Q1, mình tiến hành giải nén mã nguồn VBA của luồng `13` (`Macros/VBA/diakzouxchouz`) bằng lệnh `python oledump.py -s 13 -v .\sample.bin`.

<img width="751" height="192" alt="image" src="https://github.com/user-attachments/assets/e0359dd2-cf9c-46cd-9858-230262f9275a" />

- Kiểm tra nội dung mã nguồn gắn với `1Normal.ThisDocument`, mình ghi nhận khai báo sự kiện `Private Sub _ \n Document_open()` gọi tới thủ tục `boaxvoebxiotqueb` ngay khi tài liệu được mở.

### Q3: What malware family was this maldoc attempting to drop?

- Mình tiến hành tính giá trị băm SHA-256 của tệp mẫu `sample.bin` thu được chuỗi hash `d50d98dcc8b7043cb5c38c3de36a2ad62b293704e3cf23b0cd7450174df53fee`.
- Sau đó mình tra cứu chuỗi băm trên VirusTotal, ghi nhận các chỉ dấu nhận diện gồm `Popular threat label` (`trojan.emotet/emodldr`), `Threat categories` (`trojan`, `downloader`), `Family labels` (`emotet`, `emodldr`, `w97m`) .

### Q4: What stream is responsible for the storage of the base64-encoded string?

- Đầu tiên mình sẽ chạy công cụ `olevba` (`olevba .\sample.bin`) để phân tích tổng thể mã nguồn VBA và các thuộc tính ẩn của biểu mẫu. Ghi nhận mã macro truy xuất thuộc tính `.ControlTipText` của đối tượng `roubhaol.gaoddaicsauktheb`, đồng thời phát hiện một khối chuỗi ký tự dài bị làm rối (`o2342772g38*&gs7712ffvs626fqw...`) nằm trong biểu mẫu `roubhaol`.

<img width="1715" height="837" alt="image" src="https://github.com/user-attachments/assets/69d30277-843f-444e-a958-c3e33429f03d" />

- Sau đó mình đối chiếu tên biểu mẫu `roubhaol` sang danh sách luồng của `oledump.py` (`python oledump.py .\sample.bin`), kiểm tra nhóm luồng thuộc nhánh `Macros/roubhaol/` (từ luồng `16` đến `36`) và xác định luồng `34` (`Macros/roubhaol/i09/o`) có kích thước lớn bất thường (`15164` byte) đủ để chứa toàn bộ khối chuỗi trên.

- Cuối cùng mình trích xuất trực tiếp nội dung chuỗi trong luồng `34` bằng lệnh `python oledump.py -s 34 -S .\sample.bin`, xác nhận đây chính là nơi lưu trữ chuỗi lệnh PowerShell mã hóa Base64 bị chèn ký tự nhiễu.

<img width="1721" height="557" alt="image" src="https://github.com/user-attachments/assets/a09ac13f-4fea-4785-8df6-d2e446217c23" />

### Q5: This document contains a user-form. Provide the name.

- Quan sát danh sách các luồng OLE trích xuất từ `python oledump.py .\sample.bin`, mình thấy rằng nhánh cấu trúc giao diện `Macros/roubhaol/` (từ luồng `16` đến `36`) chứa khung `\x03VBFrame` và các điều khiển biểu mẫu con.

- Giải nén phần khai báo thuộc tính của luồng `16` bằng lệnh `python oledump.py -s 16 -v .\sample.bin` mình thấy có dòng `Attribute VB_Name = "roubhaol"` kèm định danh `Attribute VB_Base = "0{F7B023C4-B78E-4209-9503-5004D43255AC}{575DE6EB-8D5E-4153-8C58-4FAD3CE32577}"` của đối tượng UserForm, xác nhận tên biểu mẫu là `roubhaol`.

<img width="780" height="162" alt="image" src="https://github.com/user-attachments/assets/808daa9b-a478-461b-b621-5e73af30b157" />


### Q6: This document contains an obfuscated Base64 encoded string; what value is used to pad (or obfuscate) this string?

- Mình dùng kết quả trích xuất dữ liệu từ luồng `34` và quan sát thấy một chuỗi ký tự lặp lại liên tục xen kẽ giữa từng ký tự của lệnh PowerShell và khối dữ liệu Base64: `2342772g3&*gs7712ffvs626fq`.


### Q7: What is the program executed by the Base64 encoded string?

- Mình tiến hành lấy chuỗi dữ liệu thô từ luồng `34` và đưa vào công cụ CyberChef để giải mã. Sau đó mình sử dụng thao tác Find / Replace (chế độ `Simple string`) để thay thế toàn bộ chuỗi ký tự nhiễu `2342772g3&*gs7712ffvs626fq` bằng chuỗi rỗng.

<img width="1546" height="555" alt="image" src="https://github.com/user-attachments/assets/ce402e35-6bcc-4745-8ed6-ffd035220031" />

- Quan sát phần đầu chuỗi sau khi làm sạch hiển thị câu lệnh `powersheLL -e JABsAGkAZQBjAGgAcgBvAHUAaAB3AHUAdwA9...`.

### Q8: What WMI class is used to create the process to launch the Trojan?

- Mình tiếp tục từ chuỗi đã làm sạch ký tự nhiễu ở bước trước trên CyberChef, thiết lập chuỗi thao tác theo đúng thứ tự sau để giải mã hoàn chỉnh khối payload Base64:

  -  Find / Replace (chế độ `Simple string`): Tìm `2342772g3&*gs7712ffvs626fq` và thay thế bằng chuỗi rỗng.
  -  Find / Replace (chế độ `Regex`): Tìm `powersheLL -e\s+` và thay thế bằng chuỗi rỗng để cắt bỏ tiền tố gọi lệnh, chỉ giữ lại chuỗi Base64 thuần túy (`JABsAG...`).
  -  From Base64: Giải mã chuỗi Base64 theo bảng chữ cái mặc định (`A-Za-z0-9+/=`).
  -  Decode text:`UTF-16LE (1200)` để hiển thị toàn bộ mã nguồn PowerShell rõ chữ.
 
<img width="1532" height="523" alt="image" src="https://github.com/user-attachments/assets/c1f85360-761e-4c0f-bcd4-633c19c38a86" />

 - Kết quả cho thấy phần logic ở cuối đoạn script PowerShell đã giải mã, ghi nhận mã độc gọi phương thức `Create` từ lớp WMI `Win32_Process`.

### Q9: 

- Từ mã nguồn PowerShell đã giải mã trên CyberChef, mình kiểm tra biến `$jacleewyiqu` chứa danh sách các địa chỉ phân phối payload giai đoạn 2 được ngăn cách bởi ký tự `*` (`[char]42`):

<img width="1540" height="512" alt="image" src="https://github.com/user-attachments/assets/2287d236-ef9f-4126-98cb-1a6109b76dd6" />


- Kết quả cho thấy tên miền được kết nối đầu tiên là `haoqunkong.com`.
