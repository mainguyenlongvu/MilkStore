using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.Services.Service.lib;


namespace MilkStore.Services.Service;
public class PaymentService : IPaymentService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly HttpContext _httpContext;
    private readonly IOrderService _orderService;
    public PaymentService(IHttpContextAccessor httpContextAccessor, IUnitOfWork unitOfWork, IOrderService orderService)
    {
        _unitOfWork = unitOfWork;
        _httpContext = httpContextAccessor.HttpContext ?? throw new ArgumentNullException(nameof(httpContextAccessor.HttpContext));
        _orderService = orderService;
    }
    public string CreatePayment(PaymentRequest request)
    {
        VnPayLibrary vnpay = new VnPayLibrary(_httpContext);
        vnpay.AddRequestData("vnp_Version", "2.1.0");
        vnpay.AddRequestData("vnp_Command", "pay");
        vnpay.AddRequestData("vnp_TmnCode", "NMAYHP3B");
        vnpay.AddRequestData("vnp_Amount", (request.TotalAmount * 100).ToString());

        //// Lấy múi giờ Las Vegas (Pacific Time Zone)
        //TimeZoneInfo pacificZone = TimeZoneInfo.FindSystemTimeZoneById("Pacific Standard Time");
        //DateTime currentTime = TimeZoneInfo.ConvertTime(DateTime.Now, pacificZone);

        vnpay.AddRequestData("vnp_CreateDate", DateTime.Now.ToString("yyyyMMddHHmmss"));
        //vnpay.AddRequestData("vnp_CreateDate", currentTime.ToString("yyyyMMddHHmmss"));
        vnpay.AddRequestData("vnp_CurrCode", "VND");

        string clientIp = vnpay.GetClientIpAddress();
        vnpay.AddRequestData("vnp_IpAddr", clientIp);

        vnpay.AddRequestData("vnp_Locale", "vn");
        vnpay.AddRequestData("vnp_OrderInfo", request.InvoiceCode);
        vnpay.AddRequestData("vnp_OrderType", request.OrderType);
        //vnpay.AddRequestData("vnp_OrderType", "other");

        //string returnUrl = $"{Environment.GetEnvironmentVariable("CLIENT_DOMAIN")}";
        string returnUrl = $"http://milkstore-001-site1.atempurl.com//api/payment/ipn/api/payment/ipn";
        vnpay.AddRequestData("vnp_ReturnUrl", returnUrl ?? throw new Exception("SERVER_DOMAIN is not set"));
        vnpay.AddRequestData("vnp_TxnRef", DateTime.Now.ToString("yyyyMMddHHmmssfff"));
        vnpay.AddRequestData("vnp_ExpireDate", DateTime.Now.AddMinutes(30).ToString("yyyyMMddHHmmss"));

        //// Sử dụng thời gian múi giờ Las Vegas cho TxnRef và ExpireDate
        //vnpay.AddRequestData("vnp_TxnRef", currentTime.ToString("yyyyMMddHHmmssfff"));
        //vnpay.AddRequestData("vnp_ExpireDate", currentTime.AddMinutes(30).ToString("yyyyMMddHHmmss"));


        string paymentUrl = vnpay.CreateRequestUrl("https://sandbox.vnpayment.vn/paymentv2/vpcpay.html", "FC858VKW5RIH1YERAP49E2V55UOYQ6K2");

        return paymentUrl;
    }
    public async Task HandleIPN(VNPayIPNRequest request)
    {
        VnPayLibrary vnpay = new VnPayLibrary(_httpContext);
        foreach (var property in request.GetType().GetProperties())
        {
            // Lấy tên và giá trị của thuộc tính
            var name = property.Name;
            var value = property.GetValue(request)?.ToString();

            // Thêm vào _responseData nếu giá trị không phải là null
            if (!string.IsNullOrEmpty(value))
            {
                vnpay.AddResponseData(name, value);
            }
        }
        bool isValidSignature = vnpay.ValidateSignature(request.vnp_SecureHash, "FC858VKW5RIH1YERAP49E2V55UOYQ6K2");
        if (!isValidSignature)
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Signature is not valid");
        }
        if (request.vnp_ResponseCode == "00")
        {
            if (request.vnp_OrderInfo.Contains("checkout"))
            {
                string invoiceCode = request.vnp_OrderInfo.Split(" ")[^1];
                string[] parts = request.vnp_OrderInfo.Split('-');
                string shippingAddress = parts[0];
                Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(invoiceCode)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");
                var user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(order.UserId)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found");
                user.TransactionHistories.Add(new TransactionHistory
                {
                    UserId = user.Id,
                    TransactionDate = DateTime.Now,
                    Type = TransactionType.Vnpay,
                    Amount = order.DiscountedAmount,                    
                    Content = "Thanh toán đơn hàng" + order.Id
                });
                OrderModelView ord = new OrderModelView
                {
                    ShippingAddress = order.ShippingAddress,
                };
                if (shippingAddress == "InStore")
                {
                    //gọi đến service để cập nhật order
                    await _orderService.UpdateOrder(invoiceCode, ord, OrderStatus.Delivered, PaymentStatus.Paid, PaymentMethod.Online);                    
                }
                else
                {
                    //gọi đến service để cập nhật order
                    await _orderService.UpdateOrder(invoiceCode, ord, OrderStatus.Pending, PaymentStatus.Paid, PaymentMethod.Online);                    
                }
                List<OrderDetails>? orderDetails = _unitOfWork.GetRepository<OrderDetails>().Entities
                        .Where(od => od.OrderID == order.Id && od.DeletedTime == null).ToList();
                //cập nhật trạng thái của các order detail
                orderDetails.ForEach(od => od.Status = OrderDetailStatus.Ordered);
                await _unitOfWork.GetRepository<OrderDetails>().BulkUpdateAsync(orderDetails);
                await _unitOfWork.SaveAsync();
            }
            if (request.vnp_OrderInfo.Contains("Topup"))
            {
                string userID = request.vnp_OrderInfo.Split(" ")[^1];
                double amount = double.Parse(request.vnp_Amount) / 100;
                //cập nhật số dư của user
                var user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(Guid.Parse(userID))
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found");
                user.Balance += amount;

                user.TransactionHistories.Add(new TransactionHistory
                {
                    UserId = user.Id,
                    TransactionDate = DateTime.Now,
                    Type = TransactionType.UserWallet,
                    Amount = amount,
                    BalanceAfterTransaction = user.Balance,
                    Content = "Nạp tiền vào tài khoản"
                });
                await _unitOfWork.SaveAsync();
            }
        }
        else
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "ErrorCode: " + request.vnp_ResponseCode);
        }

    }

}