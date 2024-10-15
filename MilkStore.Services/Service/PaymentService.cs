using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews;
using MilkStore.ModelViews.OrderModelViews;
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
        vnpay.AddRequestData("vnp_TmnCode", "YHFJGJCV");
        vnpay.AddRequestData("vnp_Amount", (request.TotalAmount * 100).ToString());
        vnpay.AddRequestData("vnp_CreateDate", DateTime.Now.ToString("yyyyMMddHHmmss"));
        vnpay.AddRequestData("vnp_CurrCode", "VND");

        string clientIp = vnpay.GetClientIpAddress();        
        vnpay.AddRequestData("vnp_IpAddr", clientIp);

        vnpay.AddRequestData("vnp_Locale", "vn");
        vnpay.AddRequestData("vnp_OrderInfo", request.InvoiceCode);
        vnpay.AddRequestData("vnp_OrderType", request.OrderType);
        string returnUrl = $"{Environment.GetEnvironmentVariable("SERVER_DOMAIN")}/api/payment/ipn";
        vnpay.AddRequestData("vnp_ReturnUrl", returnUrl ?? throw new Exception("SERVER_DOMAIN is not set"));
        vnpay.AddRequestData("vnp_TxnRef", DateTime.Now.ToString("yyyyMMddHHmmssfff"));
        vnpay.AddRequestData("vnp_ExpireDate", DateTime.Now.AddMinutes(30).ToString("yyyyMMddHHmmss"));

        string paymentUrl = vnpay.CreateRequestUrl(Environment.GetEnvironmentVariable("VNPAY_URL") ??
            throw new Exception("VNPAY_URL is not set"), Environment.GetEnvironmentVariable("VNPAY_KEY") ??
            throw new Exception("VNPAY_KEY is not set"));

        return paymentUrl;
    }
    public async Task HandleIPN(VNPayIPNRequest request)
    {
        VnPayLibrary vnpay = new VnPayLibrary(_httpContext);

        bool isValidSignature = vnpay.ValidateSignature(request.vnp_SecureHash, Environment.GetEnvironmentVariable("VNPAY_KEY") ?? throw new Exception("VNPAY_KEY is not set"));
        if (!isValidSignature)
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Signature is not valid");
        }
        if (request.vnp_ResponseCode == "00")
        {
            string invoiceCode = request.vnp_OrderInfo.Split("+")[^1];
            Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(invoiceCode)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");

            OrderModelView ord = new OrderModelView
            {
                ShippingAddress = order.ShippingAddress,
            };
            if (request.vnp_OrderType == "InStore")
            {                
                //gọi đến service để cập nhật order
                await _orderService.UpdateOrder(invoiceCode, ord, OrderStatus.Delivered, PaymentStatus.Paid, PaymentMethod.Online);
                await _unitOfWork.SaveAsync();                
            }
            else
            {
                //gọi đến service để cập nhật order
                await _orderService.UpdateOrder(invoiceCode, ord, OrderStatus.Pending, PaymentStatus.Paid, PaymentMethod.Online);
                await _unitOfWork.SaveAsync();
            }
            List<OrderDetails>? orderDetails = _unitOfWork.GetRepository<OrderDetails>().Entities
                    .Where(od => od.OrderID == order.Id && od.DeletedTime == null).ToList();
            //cập nhật trạng thái của các order detail
            orderDetails.ForEach(od => od.Status = OrderDetailStatus.Ordered);
            await _unitOfWork.GetRepository<OrderDetails>().BulkUpdateAsync(orderDetails);
            await _unitOfWork.SaveAsync();
        }
        else
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "ErrorCode: " + request.vnp_ResponseCode);
        }

    }

}