using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews;
using MilkStore.Services.Service.lib;


namespace MilkStore.Services.Service;
public class PaymentService(IHttpContextAccessor httpContextAccessor, IUnitOfWork unitOfWork) : IPaymentService
{
    private readonly IUnitOfWork unitOfWork = unitOfWork;
    private readonly HttpContext httpContext = httpContextAccessor.HttpContext;
    public string CreatePayment(PaymentRequest request)
    {
        VnPayLibrary vnpay = new VnPayLibrary(httpContext);
        vnpay.AddRequestData("vnp_Version", "2.1.0");
        vnpay.AddRequestData("vnp_Command", "pay");
        vnpay.AddRequestData("vnp_TmnCode", "262XSFHX");
        vnpay.AddRequestData("vnp_Amount", (request.TotalAmount * 100).ToString());
        vnpay.AddRequestData("vnp_CreateDate", DateTime.Now.ToString("yyyyMMddHHmmss"));
        vnpay.AddRequestData("vnp_CurrCode", "VND");

        string clientIp = vnpay.GetClientIpAddress();

        vnpay.AddRequestData("vnp_IpAddr", clientIp);

        vnpay.AddRequestData("vnp_Locale", "vn");
        vnpay.AddRequestData("vnp_OrderInfo", "Thanh toan hoa don " + request.InvoiceCode);
        vnpay.AddRequestData("vnp_OrderType", "other");
        vnpay.AddRequestData("vnp_ReturnUrl", Environment.GetEnvironmentVariable("CLIENT_DOMAIN") ?? throw new Exception("CLIENT_DOMAIN is not set"));
        vnpay.AddRequestData("vnp_TxnRef", request.InvoiceCode);
        vnpay.AddRequestData("vnp_ExpireDate", DateTime.Now.AddMinutes(15).ToString("yyyyMMddHHmmss"));

        string paymentUrl = vnpay.CreateRequestUrl(Environment.GetEnvironmentVariable("VNPAY_URL") ??
            throw new Exception("VNPAY_URL is not set"), Environment.GetEnvironmentVariable("VNPAY_KEY") ??
            throw new Exception("VNPAY_KEY is not set"));

        return paymentUrl;
    }
    public async Task HandleIPN(VNPayIPNRequest request)
    {
        VnPayLibrary vnpay = new VnPayLibrary(httpContext);

        bool isValidSignature = vnpay.ValidateSignature(request.vnp_SecureHash, Environment.GetEnvironmentVariable("VNPAY_KEY") ?? throw new Exception("VNPAY_KEY is not set"));
        if (!isValidSignature)
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Signature is not valid");
        }
        if (request.vnp_ResponseCode == "00")
        {
            Order? order = await unitOfWork.GetRepository<Order>().GetByIdAsync(request.vnp_TxnRef)
                 ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");
            order.PaymentStatuss = PaymentStatus.Paid;
            unitOfWork.GetRepository<Order>().Update(order);
            await unitOfWork.SaveAsync();
        }
        else
        {
            throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "ErrorCode: " + request.vnp_ResponseCode);
        }

    }

}