using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.OrderDetailGiftModelView;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OrderDetailGiftController : ControllerBase
    {
        private readonly IOrderDetailGiftService _orderDetailGiftService;

        public OrderDetailGiftController(IOrderDetailGiftService orderDetailGiftService)
        {
            _orderDetailGiftService = orderDetailGiftService;
        }

        // GET: api/OrderDetailGift
        [HttpGet]
        public async Task<IActionResult> GetOrderDetailGift([FromQuery] string? id)
        {
            var result = await _orderDetailGiftService.GetOrderDetailGift(id);
            if (result == null || !result.Any())
            {
                return NotFound("No gifts found.");
            }
            return Ok(result);
        }

        // POST: api/OrderDetailGift
        [HttpPost]
        public async Task<IActionResult> CreateOrderDetailGift([FromBody] OrderDetailGiftModel orderDetailGiftModel)
        {
            await _orderDetailGiftService.CreateOrderDetailGift(orderDetailGiftModel);
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
            
        }

        // PUT: api/OrderDetailGift/{id}
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateOrderDetailGift(string id, [FromBody] OrderDetailGiftModel orderDetailGiftModel)
        {
            await _orderDetailGiftService.UpdateOrderDetailGift(id, orderDetailGiftModel);
            return Ok(BaseResponse<string>.OkResponse("Updated successfully"));
        }

        // DELETE: api/OrderDetailGift/{id}
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteOrderDetailGift(string id)
        {
            await _orderDetailGiftService.DeleteOrderDetailGift(id);
            return Ok(BaseResponse<string>.OkResponse("Deleted successfully"));
        }
    }

}
