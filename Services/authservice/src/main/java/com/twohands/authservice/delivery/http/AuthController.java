package com.twohands.authservice.delivery.http;

import com.twohands.authservice.application.auth.login.LoginCommand;
import com.twohands.authservice.application.auth.login.LoginResult;
import com.twohands.authservice.application.auth.login.LoginUseCase;
import com.twohands.authservice.application.auth.register.RegisterCommand;
import com.twohands.authservice.application.auth.register.RegisterResult;
import com.twohands.authservice.application.auth.register.RegisterUseCase;
import com.twohands.authservice.application.auth.ratelimit.RateLimitService;
import com.twohands.authservice.application.auth.verify.VerifyEmailUseCase;
import com.twohands.authservice.delivery.http.dto.LoginRequest;
import com.twohands.authservice.delivery.http.dto.LoginResponse;
import com.twohands.authservice.delivery.http.dto.RegisterRequest;
import com.twohands.authservice.delivery.http.dto.RegisterResponse;
import com.twohands.authservice.delivery.http.dto.VerifyRequest;
import com.twohands.authservice.delivery.http.dto.VerifyResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final RegisterUseCase registerUseCase;
    private final VerifyEmailUseCase verifyEmailUseCase;
    private final RateLimitService rateLimitService;
    private final LoginUseCase loginUseCase;

    public AuthController(RegisterUseCase registerUseCase,
                          VerifyEmailUseCase verifyEmailUseCase,
                          LoginUseCase loginUseCase,
                          RateLimitService rateLimitService) {
        this.registerUseCase = registerUseCase;
        this.loginUseCase = loginUseCase;
        this.verifyEmailUseCase = verifyEmailUseCase;
        this.rateLimitService = rateLimitService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest req) {
        // 1. Mapping Request DTO to a Command object to maintain Clean Architecture boundaries
        // Ánh xạ dữ liệu từ Request DTO sang đối tượng Command để giữ đúng ranh giới kiến trúc sạch
        RegisterCommand cmd = new RegisterCommand(
                req.getEmail(),
                req.getPassword(),
                req.getConfirmPassword()
        );

        // 2. Execute the registration business logic via the Use Case
        // Thực thi logic nghiệp vụ đăng ký thông qua Use Case
        RegisterResult result = registerUseCase.execute(cmd);

        // 3. Return a 200 OK response wrapped in a standardized Response DTO
        // Trả về phản hồi 200 OK được đóng gói trong một đối tượng Response chuẩn hóa
        return ResponseEntity.ok(new RegisterResponse(
                result.userId(),
                result.status(),
                "Registration successful. Please check your email to verify your account."
        ));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(
            @RequestBody VerifyRequest req,
            HttpServletRequest request
    ) {
        // 1. Extract the client's IP address for security tracking and rate limiting
        // Trích xuất địa chỉ IP của khách hàng để theo dõi bảo mật và giới hạn tần suất gửi tin
        String ip = getClientIp(request);

        // 2. Prevent brute-force attacks by checking the request frequency from this IP
        // Ngăn chặn tấn công dò mã (brute-force) bằng cách kiểm tra tần suất yêu cầu từ IP này
        rateLimitService.check("verify", ip);

        // 3. Execute the core business logic to validate the OTP and activate the user account
        // Thực thi logic nghiệp vụ cốt lõi để kiểm tra mã OTP và kích hoạt tài khoản người dùng
        verifyEmailUseCase.execute(req.getEmail(), req.getOtp());

        // 4. Return a success response if the OTP is valid and the account is activated
        // Trả về phản hồi thành công nếu mã OTP hợp lệ và tài khoản đã được kích hoạt
        return ResponseEntity.ok(new VerifyResponse("Email verified successfully. Your account is now active."));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest req,
            HttpServletRequest request
    ) {
        // 1. Collect metadata for security audit and session management
        // Thu thập siêu dữ liệu để kiểm toán bảo mật và quản lý phiên làm việc
        
        // Identify the actual origin IP address of the client
        // Xác định địa chỉ IP gốc thực tế của khách hàng
        String ip = getClientIp(request);        
        String userAgent = request.getHeader("User-Agent"); // Identify browser/app type (Nhận diện trình duyệt/ứng dụng)
        String deviceId = request.getHeader("X-Device-Id"); // Unique ID for hardware tracking (ID duy nhất để theo dõi thiết bị)

        // 2. Encapsulate data into a Command object (CQRS pattern influence)
        // Đóng gói dữ liệu vào đối tượng Command (ảnh hưởng từ mô hình CQRS)
        LoginCommand cmd = new LoginCommand(
                req.getEmail(),
                req.getPassword(),
                ip,
                userAgent,
                deviceId
        );

        // 3. Delegate authentication logic to the specialized Use Case
        // Ủy thác logic xác thực cho Use Case chuyên biệt xử lý
        LoginResult result = loginUseCase.execute(cmd);

        // 4. Map the internal result to a DTO for the client response
        // Ánh xạ kết quả nội bộ sang DTO để trả về cho khách hàng
        LoginResponse.UserSummary userSummary = new LoginResponse.UserSummary(
                result.userId(),
                result.email(),
                result.status(),
                result.emailVerified(),
                result.roles()
        );

        // 5. Return tokens and user info (Success 200 OK)
        // Trả về các token và thông tin người dùng (Thành công 200 OK)
        return ResponseEntity.ok(new LoginResponse(
                result.accessToken(),
                result.refreshToken(),
                result.tokenType(),
                result.expiresIn(),
                userSummary
        ));
    }

    private String getClientIp(HttpServletRequest request) {
        // 1. Check the 'X-Forwarded-For' header for the real client IP address
        // Kiểm tra header 'X-Forwarded-For' để tìm địa chỉ IP thực của khách hàng
        String ip = request.getHeader("X-Forwarded-For");

        // 2. If the header is missing, empty, or 'unknown', fallback to the direct remote address
        // Nếu header bị thiếu, trống hoặc mang giá trị 'unknown', quay lại dùng địa chỉ kết nối trực tiếp
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            // Retrieve the IP address of the client or last proxy that sent the request
            // Lấy địa chỉ IP của khách hàng hoặc proxy cuối cùng gửi yêu cầu đến
            ip = request.getRemoteAddr();
        }
        
        // 3. Return the identified IP address (could be a comma-separated list if multiple proxies are used)
        // Trả về địa chỉ IP đã xác định (có thể là danh sách cách nhau bởi dấu phẩy nếu qua nhiều proxy)
        return ip;
    }
}
