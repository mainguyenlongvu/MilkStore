using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CheckoutController : ControllerBase
    {
        private readonly ITransactionService _transactionService;

        public CheckoutController(ITransactionService transactionService)
        {
            _transactionService = transactionService;
        }

        [HttpPost]
        public async Task<IActionResult> Checkout([FromQuery] PaymentMethod paymentMethod, [FromQuery] List<string>? voucherCode, [FromQuery] ShippingType shippingAddress)
        {
            string result = await _transactionService.Checkout(paymentMethod, voucherCode, shippingAddress);
            return Ok(BaseResponse<string>.OkResponse(result));
        }
    }
}
