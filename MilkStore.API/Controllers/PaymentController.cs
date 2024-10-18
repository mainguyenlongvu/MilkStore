using Microsoft.AspNetCore.Mvc;
using MilkStore.Core.Base;
using MilkStore.ModelViews;
using MilkStore.Services.Service;
[ApiController]
[Route("api/[controller]")]

public class PaymentController(IPaymentService paymentService) : ControllerBase
{
    private readonly IPaymentService paymentService = paymentService;

    [HttpPost("create_payment")]
    public IActionResult CreatePayment(PaymentRequest request)
    {
        string paymentUrl = paymentService.CreatePayment(request);
        return Ok(BaseResponse<object>.OkResponse(paymentUrl));
    }
    [HttpGet("IPN")]
    public async Task<IActionResult> IPN([FromQuery] VNPayIPNRequest request)
    {
        await paymentService.HandleIPN(request);        
        return Ok(BaseResponse<object>.OkResponse("Thanh toán thành công!"));
    }

}
